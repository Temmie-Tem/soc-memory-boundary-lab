#!/usr/bin/env python3
"""Inventory the exact A90 TrustZone XPU policy around the ICB remapper.

This is a host-only parser.  It performs no device or MMIO access and emits no
firmware bytes.  The exact TrustZone, devcfg, and retained boot-log inputs are
pinned so the result cannot silently drift to another build.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import struct
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools.xbl_dcb_inventory import LoadSegment, parse_elf64_load_segments
    from tools.xbl_memory_pipeline_inventory import (
        djb2,
        file_offset_to_vaddr,
        read_c_string_vaddr,
        read_vaddr,
        unique_bytes_offset,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from xbl_dcb_inventory import LoadSegment, parse_elf64_load_segments
    from xbl_memory_pipeline_inventory import (
        djb2,
        file_offset_to_vaddr,
        read_c_string_vaddr,
        read_vaddr,
        unique_bytes_offset,
    )


PINS: Mapping[str, Mapping[str, object]] = {
    "trustzone": {
        "size": 4_194_304,
        "sha256": "a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab",
    },
    "devcfg": {
        "size": 131_072,
        "sha256": "0399578253dd293dfc961c6a1077f660834df3ae5e1d65555f4225e327a03d14",
    },
    "retained_boot_log": {
        "size": 2_097_136,
        "sha256": "8701d073e86728790c33f05dce21891ca3454f5b778d92285ce3b5bc33216b93",
    },
}

TESTED_PHYSICAL_ADDRESS = 0x09248080

XPU_REGISTRY_VADDR = 0x1C1579E0
XPU_REGISTRY_COUNT_VADDR = 0x1C157E60
XPU_REGISTRY_RECORD_SIZE = 24
XPU_REGISTRY_EXPECTED_COUNT = 48

POLICY_TABLES: Mapping[str, Mapping[str, int | str]] = {
    "selector_result_lt_2": {
        "table_vaddr": 0x1C122100,
        "count_vaddr": 0x1C1227B8,
        "expected_count": 43,
        "selector_predicate": "selector_result_byte < 2",
    },
    "selector_result_ge_2": {
        "table_vaddr": 0x1C121250,
        "count_vaddr": 0x1C121930,
        "expected_count": 44,
        "selector_predicate": "selector_result_byte >= 2",
    },
}
POLICY_DESCRIPTOR_SIZE = 40
MPU_REGION_RECORD_SIZE = 32

RELEVANT_XPU_IDS: Mapping[str, int] = {
    "BIMC_MPU0": 0x2E,
    "BIMC_MPU1": 0x2F,
    "BIMC_MPU2": 0x3F,
    "BIMC_MPU3": 0x40,
    "LLCC_BROADCAST_MPU": 0x3A,
    "DC_NOC_BROADCAST_MPU": 0x3C,
    "DC_NOC_NON_BROADCAST_MPU": 0x3D,
    "MEMNOC_MS_MPU": 0x4B,
    "DC_NOC_SHRM_MPU": 0x4D,
}

CRITICAL_REGION_EXPECTED = {
    "index": 11,
    "flags": 0x09,
    "read_vmid": 0x80000000,
    "write_vmid": 0,
    "start": 0x09248000,
    "end_exclusive": 0x09249000,
}

ERROR_ROUTER_VADDR = 0x1C155350
ERROR_ROUTER_BANK_SIZES = (32, 16)
ERROR_ROUTER_EXPECTED: Mapping[tuple[int, int], int] = {
    (0, 20): 0x4B,
    (0, 25): 0x2E,
    (0, 26): 0x2F,
    (0, 27): 0x3F,
    (0, 28): 0x40,
    (0, 29): 0x3C,
    (0, 31): 0x3D,
    (1, 13): 0x4D,
}

DEVCFG_PROPERTY_SOURCE_VADDR = 0x1C00D040
DEVCFG_DEVICE_ENTRY_SIZE = 0x28
DEVCFG_DEVICE_PATH = "/ac/xpu"
DEVCFG_PROPERTY_NAME = "disable_xpu_ac"
DAL_UINT32_PROPERTY_TYPE = 0x02
DAL_PROPERTY_END_MARKER = 0xFF00FF00

FUNCTION_FINGERPRINTS: Mapping[str, Mapping[str, object]] = {
    "policy_selector": {
        "start": 0x1C0A2DFC,
        "end": 0x1C0A2EC4,
        "sha256": "1bb3cba7b5fbcfe7914c59918caa09c84368fd0d84a8214fe3eed12d6dc3b67b",
    },
    "static_config_loop": {
        "start": 0x1C0A9C7C,
        "end": 0x1C0A9D5C,
        "sha256": "9cd2e52d6efbd30a2c77332624b17a9c3da8e939419187cce90333a64861a3de",
    },
    "mpu_partition_config": {
        "start": 0x1C0AA51C,
        "end": 0x1C0AA7E4,
        "sha256": "72bc8b1c6cfcfba1d566e43ab37dfc03ed7568a50950f8b636f58319ed87da6f",
    },
    "hal_config_resource_group_wrapper": {
        "start": 0x1C0FAEA8,
        "end": 0x1C0FAF5C,
        "sha256": "17527d70ce365e75685a110d993b66f259ab5543630408de5da5146b09e91685",
    },
    "xpu_registry_lookup": {
        "start": 0x1C0FC890,
        "end": 0x1C0FCA1C,
        "sha256": "bc25e3d06839f7856b067f08a02057585805b4415d61b96b3f5023b27e27afda",
    },
}

PINNED_INSTRUCTIONS: Mapping[int, int] = {
    # Boot initialization calls the static-config loop with the selected table.
    0x1C0A25A4: 0x94001DB6,
    # The static-config loop calls the per-device configuration routine.
    0x1C0A9CD8: 0x97FFFE43,
    # MPU records load read/write masks and 64-bit start/end at these offsets.
    0x1C0AA58C: 0x29416297,
    0x1C0AA5B8: 0xA9412688,
    # Read bit 31 becomes client-permission byte 0 bit 4.
    0x1C0AA67C: 0x37F80468,
    0x1C0AA70C: 0x321C014A,
    # Flag bit 3 selects TZ ownership and grants the owner read/write fields.
    0x1C0AA6A0: 0x371805A8,
    0x1C0AA760: 0x32000108,
    0x1C0AA764: 0x321D0129,
    # Region index is passed to the HAL resource-group wrapper.
    0x1C0AA78C: 0x79400281,
    0x1C0AA798: 0x940141C4,
}

COMPARATIVE_SOURCE = {
    "status": "COMPARATIVE_NOT_EXACT_SM8150_SOURCE",
    "repository": "David112x/android-firmware-qti-sdm660",
    "commit": "b5e5bb9ed6c92442fd502b3e726d7c8024dc0763",
    "files": [
        {
            "path": "trustzone_images/core/securemsm/accesscontrol/api/AccessControlTz.h",
            "sha256": "b31edbf4afd41d8d5d4faa0b62ab01f74b7fd149286ee0486b7bbe45bca6f724",
            "relevance": (
                "Defines the 32-byte tzbsp_mpu_rg_t layout, xPU3 owner flags, "
                "and AC_VM_HLOS=3."
            ),
        },
        {
            "path": "trustzone_images/core/kernel/xpu3/hal/inc/HALxpu3.h",
            "sha256": "07291481f1b28c201ad3043692a53188ccc8dae476c207bea06eafd6c620b414",
            "relevance": (
                "Defines the two-byte XPU3 client-permission bitfield and "
                "HAL_XPU2_CONFIG_SECURE=0."
            ),
        },
        {
            "path": (
                "trustzone_images/core/securemsm/accesscontrol/build/qsee/"
                "A53_64/KAJAANAA/src/components/xpu/v3/ACXpu.o"
            ),
            "sha256": "376ddb769505a29895b88f2af079e9ddf8c154faf087d0dcd2f851a840cd4fe0",
            "relevance": (
                "Unstripped comparative object names the matching conversion "
                "routine tzbsp_mpu_partition_config."
            ),
        },
    ],
    "claim_boundary": (
        "The comparative source supplies names and field documentation only; "
        "all SM8150 address, branch, and policy claims are independently pinned "
        "to the exact A90 firmware bytes."
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_pinned_bytes(
    label: str, data: bytes, pin: Mapping[str, object]
) -> dict[str, object]:
    expected_size = int(pin["size"])
    expected_sha256 = str(pin["sha256"])
    actual_sha256 = sha256(data)
    if len(data) != expected_size:
        raise ValueError(
            f"{label} size mismatch: {len(data)} != pinned {expected_size}"
        )
    if actual_sha256 != expected_sha256:
        raise ValueError(
            f"{label} SHA-256 mismatch: {actual_sha256} != pinned {expected_sha256}"
        )
    return {
        "size": len(data),
        "sha256": actual_sha256,
        "pin_verified": True,
    }


def parse_xpu_registry(
    data: bytes,
    segments: Sequence[LoadSegment],
    table_vaddr: int = XPU_REGISTRY_VADDR,
    count_vaddr: int = XPU_REGISTRY_COUNT_VADDR,
    expected_count: int | None = XPU_REGISTRY_EXPECTED_COUNT,
) -> list[dict[str, object]]:
    count = struct.unpack("<I", read_vaddr(data, segments, count_vaddr, 4))[0]
    if expected_count is not None and count != expected_count:
        raise ValueError(f"XPU registry count {count} != expected {expected_count}")
    records: list[dict[str, object]] = []
    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    for index in range(count):
        record_vaddr = table_vaddr + index * XPU_REGISTRY_RECORD_SIZE
        resource_id, base, name_vaddr = struct.unpack(
            "<QQQ", read_vaddr(data, segments, record_vaddr, 24)
        )
        name = read_c_string_vaddr(data, segments, name_vaddr)
        if resource_id >= 0x100:
            raise ValueError(f"registry resource id 0x{resource_id:x} is implausible")
        if base == 0 or base >= 1 << 32 or base & 0xFFF:
            raise ValueError(f"registry base 0x{base:x} is not a 32-bit page base")
        if resource_id in seen_ids or name in seen_names:
            raise ValueError(f"duplicate XPU registry record id={resource_id} name={name}")
        seen_ids.add(resource_id)
        seen_names.add(name)
        records.append(
            {
                "index": index,
                "resource_id": resource_id,
                "base": base,
                "name": name,
                "record_vaddr": record_vaddr,
                "name_vaddr": name_vaddr,
            }
        )
    return records


def parse_policy_descriptors(
    data: bytes,
    segments: Sequence[LoadSegment],
    table_vaddr: int,
    count: int,
) -> list[dict[str, int]]:
    records = []
    for index in range(count):
        vaddr = table_vaddr + index * POLICY_DESCRIPTOR_SIZE
        raw = read_vaddr(data, segments, vaddr, POLICY_DESCRIPTOR_SIZE)
        base, resource_id, flags, cfg_read, cfg_write, region_count, region_vaddr = (
            struct.unpack("<QHHII4xH6xQ", raw)
        )
        records.append(
            {
                "index": index,
                "vaddr": vaddr,
                "base": base,
                "resource_id": resource_id,
                "flags": flags,
                "unmapped_read_vmid": cfg_read,
                "unmapped_write_vmid": cfg_write,
                "region_count": region_count,
                "region_vaddr": region_vaddr,
            }
        )
    return records


def parse_mpu_regions(
    data: bytes,
    segments: Sequence[LoadSegment],
    table_vaddr: int,
    count: int,
) -> list[dict[str, int]]:
    records = []
    for ordinal in range(count):
        vaddr = table_vaddr + ordinal * MPU_REGION_RECORD_SIZE
        index, flags, read_vmid, write_vmid, start, end = struct.unpack(
            "<IIIIQQ", read_vaddr(data, segments, vaddr, MPU_REGION_RECORD_SIZE)
        )
        records.append(
            {
                "ordinal": ordinal,
                "vaddr": vaddr,
                "index": index,
                "flags": flags,
                "read_vmid": read_vmid,
                "write_vmid": write_vmid,
                "start": start,
                "end_exclusive": end,
            }
        )
    return records


def region_contains(region: Mapping[str, int], address: int) -> bool:
    return int(region["start"]) <= address < int(region["end_exclusive"])


def vmids_to_perm(read_vmids: int, write_vmids: int) -> int:
    """Expand 16 read/write VMID bits into two permission bits per VMID."""
    result = 0
    for vmid in range(16):
        if read_vmids & (1 << vmid):
            result |= 1 << (vmid * 2)
        if write_vmids & (1 << vmid):
            result |= 1 << (vmid * 2 + 1)
    return result


def decode_mpu_region_permissions(region: Mapping[str, int]) -> dict[str, object]:
    """Replay the exact SM8150 tzbsp_mpu_partition_config bit mapping."""
    flags = int(region["flags"])
    read_vmid = int(region["read_vmid"])
    write_vmid = int(region["write_vmid"])
    standard_mask = 0x40FFFFFF

    perm_low = vmids_to_perm(read_vmid & 0xFFFF, write_vmid & 0xFFFF)
    perm_high = vmids_to_perm((read_vmid >> 16) & 0xFF, (write_vmid >> 16) & 0xFF)

    client_byte0 = 0x08 if read_vmid & standard_mask else 0
    client_byte1 = 0x01 if write_vmid & standard_mask else 0
    if read_vmid & (1 << 28):
        client_byte0 |= 0x01
    if write_vmid & (1 << 28):
        client_byte1 |= 0x08
    if read_vmid & (1 << 31):
        client_byte0 |= 0x10
    if write_vmid & (1 << 31):
        client_byte1 |= 0x02
    if read_vmid & (1 << 29):
        client_byte0 |= 0x20
    if write_vmid & (1 << 29):
        client_byte1 |= 0x04

    if flags & (1 << 2):
        owner = "MSA"
        config_type = 2
        client_byte0 |= 0x10
        client_byte1 |= 0x02
    elif flags & (1 << 3):
        owner = "TZ"
        config_type = 0
        client_byte0 |= 0x01
        client_byte1 |= 0x08
    elif flags & (1 << 5):
        owner = "SP"
        config_type = 3
        client_byte0 |= 0x20
        client_byte1 |= 0x04
    elif flags & (1 << 6):
        owner = "UNOWNED"
        config_type = 4
    else:
        owner = "HYP_OR_BASE_NONSECURE"
        config_type = 1
        client_byte0 |= 0x08
        client_byte1 |= 0x01

    fields = {
        "secure_client_ro_vector": client_byte0 & 0x7,
        "nonsecure_client_ro_vector": (client_byte0 >> 3) & 0x7,
        "nonsecure_client_wo_vector": client_byte1 & 0x7,
        "secure_client_wo_vector": (client_byte1 >> 3) & 0x7,
    }
    hlos_vmid = 3
    hlos_mask = 1 << hlos_vmid
    return {
        "owner": owner,
        "hal_config_type": config_type,
        "multi_vmid_permission_words": [
            f"0x{perm_low:08x}",
            f"0x{perm_high:08x}",
        ],
        "client_permission_bytes": [
            f"0x{client_byte0:02x}",
            f"0x{client_byte1:02x}",
        ],
        "client_permission_fields": fields,
        "read_bit31_maps_to_same_ro_slot_as_msa_owner": bool(
            read_vmid & (1 << 31)
        ),
        "hlos_vmid_comparative_id": hlos_vmid,
        "hlos_vmid_mask": f"0x{hlos_mask:08x}",
        "hlos_present_in_read_mask": bool(read_vmid & hlos_mask),
        "hlos_present_in_write_mask": bool(write_vmid & hlos_mask),
        "standard_vmid_read_bits": f"0x{read_vmid & standard_mask:08x}",
        "standard_vmid_write_bits": f"0x{write_vmid & standard_mask:08x}",
        "static_policy_interpretation": (
            "TZ-owned; TZ owner read/write; MSA-class read-only; no standard "
            "VMID permission and no HLOS VMID bit"
        ),
        "runtime_activation": "UNKNOWN_WITH_SUPPORTING_BOOT_EVIDENCE",
    }


def parse_error_router(
    data: bytes,
    segments: Sequence[LoadSegment],
    table_vaddr: int = ERROR_ROUTER_VADDR,
    bank_sizes: Sequence[int] = ERROR_ROUTER_BANK_SIZES,
) -> list[dict[str, int]]:
    records = []
    offset = 0
    for bank, count in enumerate(bank_sizes):
        for ordinal in range(count):
            bit, resource_id = struct.unpack(
                "BB", read_vaddr(data, segments, table_vaddr + offset, 2)
            )
            if bit != ordinal:
                raise ValueError(
                    f"error-router bank {bank} ordinal {ordinal} carries bit {bit}"
                )
            records.append(
                {
                    "bank": bank,
                    "bit": bit,
                    "resource_id": resource_id,
                    "vaddr": table_vaddr + offset,
                }
            )
            offset += 2
    return records


def parse_dal_u32_property(
    data: bytes,
    segments: Sequence[LoadSegment],
    source_vaddr: int = DEVCFG_PROPERTY_SOURCE_VADDR,
    device_path: str = DEVCFG_DEVICE_PATH,
    property_name: str = DEVCFG_PROPERTY_NAME,
    device_entry_size: int = DEVCFG_DEVICE_ENTRY_SIZE,
) -> dict[str, object]:
    source = read_vaddr(data, segments, source_vaddr, 0x20)
    propbin_vaddr, struct_table_vaddr = struct.unpack_from("<QQ", source, 0)
    device_count = struct.unpack_from("<I", source, 0x10)[0]
    device_table_vaddr = struct.unpack_from("<Q", source, 0x18)[0]

    path_file_offset = unique_bytes_offset(data, device_path.encode() + b"\0")
    path_vaddr = file_offset_to_vaddr(
        segments, path_file_offset, len(device_path) + 1
    )
    expected_hash = djb2(device_path)
    match: tuple[int, int, int] | None = None
    for index in range(device_count):
        entry_vaddr = device_table_vaddr + index * device_entry_size
        entry = read_vaddr(data, segments, entry_vaddr, 16)
        name_pointer, name_hash, property_offset = struct.unpack("<QII", entry)
        if name_pointer == path_vaddr and name_hash == expected_hash:
            if match is not None:
                raise ValueError(f"multiple DAL entries for {device_path}")
            match = (index, entry_vaddr, property_offset)
    if match is None:
        raise ValueError(f"DAL entry for {device_path} not found")

    index, entry_vaddr, property_offset = match
    property_vaddr = propbin_vaddr + property_offset
    header, value, end_marker = struct.unpack(
        "<III", read_vaddr(data, segments, property_vaddr, 12)
    )
    property_type = header >> 24
    name_offset = header & 0x003FFFFF
    string_table_offset = struct.unpack(
        "<I", read_vaddr(data, segments, propbin_vaddr + 4, 4)
    )[0]
    parsed_name = read_c_string_vaddr(
        data,
        segments,
        propbin_vaddr + string_table_offset + name_offset,
    )
    if property_type != DAL_UINT32_PROPERTY_TYPE:
        raise ValueError(f"DAL property type 0x{property_type:x} is not uint32")
    if parsed_name != property_name:
        raise ValueError(f"DAL property name {parsed_name!r} != {property_name!r}")
    if end_marker != DAL_PROPERTY_END_MARKER:
        raise ValueError(f"DAL property end marker 0x{end_marker:08x} is invalid")
    return {
        "source_vaddr": source_vaddr,
        "propbin_vaddr": propbin_vaddr,
        "struct_table_vaddr": struct_table_vaddr,
        "device_count": device_count,
        "device_table_vaddr": device_table_vaddr,
        "device_index": index,
        "device_entry_vaddr": entry_vaddr,
        "device_path": device_path,
        "device_path_vaddr": path_vaddr,
        "device_hash": expected_hash,
        "property_offset": property_offset,
        "property_vaddr": property_vaddr,
        "property_name": parsed_name,
        "property_type": property_type,
        "value": value,
        "end_marker": end_marker,
    }


def verify_tz_code(
    data: bytes, segments: Sequence[LoadSegment]
) -> dict[str, object]:
    functions: dict[str, object] = {}
    for name, expected in FUNCTION_FINGERPRINTS.items():
        start = int(expected["start"])
        end = int(expected["end"])
        block = read_vaddr(data, segments, start, end - start)
        digest = sha256(block)
        if digest != expected["sha256"]:
            raise ValueError(
                f"TrustZone function {name} hash mismatch: "
                f"{digest} != {expected['sha256']}"
            )
        functions[name] = {
            "start": f"0x{start:x}",
            "end_exclusive": f"0x{end:x}",
            "size": end - start,
            "sha256": digest,
        }

    instructions = []
    for address, expected_word in PINNED_INSTRUCTIONS.items():
        observed = struct.unpack("<I", read_vaddr(data, segments, address, 4))[0]
        if observed != expected_word:
            raise ValueError(
                f"TrustZone instruction mismatch at 0x{address:x}: "
                f"0x{observed:08x} != 0x{expected_word:08x}"
            )
        instructions.append(
            {"address": f"0x{address:x}", "word": f"0x{observed:08x}"}
        )
    return {"functions": functions, "pinned_instruction_words": instructions}


def _format_registry(record: Mapping[str, object]) -> dict[str, object]:
    return {
        "index": record["index"],
        "resource_id": f"0x{int(record['resource_id']):x}",
        "base": f"0x{int(record['base']):08x}",
        "name": record["name"],
        "record_vaddr": f"0x{int(record['record_vaddr']):x}",
        "name_vaddr": f"0x{int(record['name_vaddr']):x}",
    }


def _format_descriptor(
    record: Mapping[str, int], name: str
) -> dict[str, object]:
    return {
        "index": record["index"],
        "vaddr": f"0x{record['vaddr']:x}",
        "name": name,
        "resource_id": f"0x{record['resource_id']:x}",
        "base": f"0x{record['base']:08x}",
        "flags": f"0x{record['flags']:x}",
        "unmapped_read_vmid": f"0x{record['unmapped_read_vmid']:08x}",
        "unmapped_write_vmid": f"0x{record['unmapped_write_vmid']:08x}",
        "region_count": record["region_count"],
        "region_vaddr": f"0x{record['region_vaddr']:x}",
    }


def _format_region(record: Mapping[str, int]) -> dict[str, object]:
    return {
        "ordinal": record["ordinal"],
        "vaddr": f"0x{record['vaddr']:x}",
        "index": record["index"],
        "flags": f"0x{record['flags']:x}",
        "read_vmid": f"0x{record['read_vmid']:08x}",
        "write_vmid": f"0x{record['write_vmid']:08x}",
        "start": f"0x{record['start']:08x}",
        "end_exclusive": f"0x{record['end_exclusive']:08x}",
        "size": record["end_exclusive"] - record["start"],
    }


def analyze(tz_data: bytes, devcfg_data: bytes, boot_log_data: bytes) -> dict[str, object]:
    tz_segments = parse_elf64_load_segments(tz_data)
    devcfg_segments = parse_elf64_load_segments(devcfg_data)
    registry = parse_xpu_registry(tz_data, tz_segments)
    registry_by_id = {int(record["resource_id"]): record for record in registry}
    registry_by_name = {str(record["name"]): record for record in registry}

    for name, resource_id in RELEVANT_XPU_IDS.items():
        record = registry_by_name.get(name)
        if record is None or int(record["resource_id"]) != resource_id:
            raise ValueError(f"relevant XPU registry binding mismatch for {name}")

    policies: dict[str, object] = {}
    critical_raw_records: list[bytes] = []
    bimc_ids = {RELEVANT_XPU_IDS[f"BIMC_MPU{index}"] for index in range(4)}
    for label, specification in POLICY_TABLES.items():
        table_vaddr = int(specification["table_vaddr"])
        count_vaddr = int(specification["count_vaddr"])
        expected_count = int(specification["expected_count"])
        count = struct.unpack(
            "<I", read_vaddr(tz_data, tz_segments, count_vaddr, 4)
        )[0]
        if count != expected_count:
            raise ValueError(f"{label} count {count} != expected {expected_count}")
        descriptors = parse_policy_descriptors(
            tz_data, tz_segments, table_vaddr, count
        )
        for descriptor in descriptors:
            resource_id = descriptor["resource_id"]
            registry_record = registry_by_id.get(resource_id)
            if registry_record is None:
                raise ValueError(f"policy id 0x{resource_id:x} absent from registry")
            if int(registry_record["base"]) != descriptor["base"]:
                raise ValueError(f"policy/registry base mismatch for id 0x{resource_id:x}")

        dc_matches = [
            descriptor
            for descriptor in descriptors
            if descriptor["resource_id"] == RELEVANT_XPU_IDS["DC_NOC_BROADCAST_MPU"]
        ]
        if len(dc_matches) != 1:
            raise ValueError(f"{label} has {len(dc_matches)} DC_NOC_BROADCAST_MPUs")
        dc = dc_matches[0]
        if dc["base"] != 0x090E0000 or dc["region_count"] != 40:
            raise ValueError(f"{label} DC_NOC_BROADCAST_MPU descriptor mismatch")
        regions = parse_mpu_regions(
            tz_data, tz_segments, dc["region_vaddr"], dc["region_count"]
        )
        containing = [
            region for region in regions if region_contains(region, TESTED_PHYSICAL_ADDRESS)
        ]
        if len(containing) != 1:
            raise ValueError(
                f"{label} has {len(containing)} regions covering "
                f"0x{TESTED_PHYSICAL_ADDRESS:x}"
            )
        critical = containing[0]
        for key, expected in CRITICAL_REGION_EXPECTED.items():
            if critical[key] != expected:
                raise ValueError(
                    f"{label} critical region {key}={critical[key]!r} != {expected!r}"
                )
        critical_raw = read_vaddr(
            tz_data, tz_segments, critical["vaddr"], MPU_REGION_RECORD_SIZE
        )
        critical_raw_records.append(critical_raw)
        neighborhood = [
            _format_region(region)
            for region in regions
            if 0x09240000 <= region["start"] < 0x09250000
        ]
        descriptor_ids = {descriptor["resource_id"] for descriptor in descriptors}
        policies[label] = {
            "selector_predicate": specification["selector_predicate"],
            "table_vaddr": f"0x{table_vaddr:x}",
            "count_vaddr": f"0x{count_vaddr:x}",
            "count": count,
            "descriptor_table_sha256": sha256(
                read_vaddr(
                    tz_data,
                    tz_segments,
                    table_vaddr,
                    count * POLICY_DESCRIPTOR_SIZE,
                )
            ),
            "descriptors": [
                _format_descriptor(
                    descriptor, str(registry_by_id[descriptor["resource_id"]]["name"])
                )
                for descriptor in descriptors
            ],
            "bimc_mpu_ids_present": [
                f"0x{resource_id:x}"
                for resource_id in sorted(descriptor_ids & bimc_ids)
            ],
            "dc_noc_broadcast_mpu": _format_descriptor(
                dc, "DC_NOC_BROADCAST_MPU"
            ),
            "critical_region": _format_region(critical),
            "critical_region_raw_sha256": sha256(critical_raw),
            "critical_permission_decode": decode_mpu_region_permissions(critical),
            "nearby_qhs_llcc_regions": neighborhood,
        }

    if len(set(critical_raw_records)) != 1:
        raise ValueError("the two selector branches do not carry the same critical region")

    error_router = parse_error_router(tz_data, tz_segments)
    error_by_position = {
        (record["bank"], record["bit"]): record["resource_id"]
        for record in error_router
    }
    for position, expected_id in ERROR_ROUTER_EXPECTED.items():
        if error_by_position.get(position) != expected_id:
            raise ValueError(f"error-router mismatch at {position}")
    relevant_error_routes = []
    for position, resource_id in ERROR_ROUTER_EXPECTED.items():
        relevant_error_routes.append(
            {
                "status_bank": position[0],
                "status_bit": position[1],
                "resource_id": f"0x{resource_id:x}",
                "name": registry_by_id[resource_id]["name"],
            }
        )

    devcfg = parse_dal_u32_property(devcfg_data, devcfg_segments)
    if devcfg["value"] != 0:
        raise ValueError("exact devcfg disables or alters XPU access control")

    code = verify_tz_code(tz_data, tz_segments)
    xpu_strings = [
        "HAL_XPU2_ERROR_F_CONFIG_PORT",
        "HAL_XPU2_ERROR_F_CLIENT_PORT",
        "HAL_XPU2_BUS_F_APROTNS",
        "HAL_XPU2_BUS_F_AWRITE",
    ]
    missing_strings = [
        value for value in xpu_strings if value.encode() + b"\0" not in tz_data
    ]
    if missing_strings:
        raise ValueError(f"missing exact TZ XPU error strings: {missing_strings}")

    watchdog_count = boot_log_data.count(b"Non Secure Watchdog Bark")
    xpu_report_count = boot_log_data.count(b"print_xpu_info: START")
    xpu_unparsed_count = boot_log_data.count(
        b"tz log is encrypted or not parsed yet!"
    )
    if watchdog_count < 1 or xpu_report_count < 1 or xpu_unparsed_count < 1:
        raise ValueError("retained boot log lacks the pinned watchdog/XPU boundary")

    return {
        "tested_access": {
            "physical_address": f"0x{TESTED_PHYSICAL_ADDRESS:08x}",
            "width_bits": 32,
            "operation": "one fixed EL1 load after successful __ioremap",
            "observed_value": None,
            "terminal_observation": "NON_SECURE_WATCHDOG_BEFORE_MSM_READL",
        },
        "trustzone_registry": {
            "table_vaddr": f"0x{XPU_REGISTRY_VADDR:x}",
            "count_vaddr": f"0x{XPU_REGISTRY_COUNT_VADDR:x}",
            "count": len(registry),
            "record_size": XPU_REGISTRY_RECORD_SIZE,
            "table_sha256": sha256(
                read_vaddr(
                    tz_data,
                    tz_segments,
                    XPU_REGISTRY_VADDR,
                    len(registry) * XPU_REGISTRY_RECORD_SIZE,
                )
            ),
            "records": [_format_registry(record) for record in registry],
        },
        "policy_selector": {
            "function": code["functions"]["policy_selector"],
            "branch_invariant": (
                "Both embedded selector branches contain the identical "
                "DC_NOC_BROADCAST_MPU region covering the tested address."
            ),
            "runtime_selector_result": "UNKNOWN_NOT_REQUIRED_FOR_CRITICAL_REGION",
        },
        "policy_tables": policies,
        "critical_policy_result": {
            "resource": "DC_NOC_BROADCAST_MPU",
            "resource_id": "0x3c",
            "xpu_mmio_base": "0x090e0000",
            "covered_range": "0x09248000-0x09249000 (end exclusive)",
            "tested_address_covered": True,
            "selector_branch_invariant": True,
            "owner": "TZ",
            "read_vmid": "0x80000000",
            "write_vmid": "0x00000000",
            "exact_constructed_client_permission_bytes": ["0x11", "0x08"],
            "standard_multi_vmid_permission_words": ["0x00000000", "0x00000000"],
            "hlos_granted_by_static_record": False,
            "msa_class_read_only_grant": True,
            "runtime_register_readback": "UNKNOWN",
        },
        "policy_absence_boundary": {
            "bimc_mpu_ids": ["0x2e", "0x2f", "0x3f", "0x40"],
            "present_in_either_embedded_policy_list": False,
            "interpretation": (
                "PROVED absent from these two TZ static policy lists only; "
                "initialization by XBL, another secure component, hardware "
                "defaults, or another path remains UNKNOWN."
            ),
        },
        "error_routing": {
            "table_vaddr": f"0x{ERROR_ROUTER_VADDR:x}",
            "parsed_bank_sizes": list(ERROR_ROUTER_BANK_SIZES),
            "table_sha256": sha256(
                read_vaddr(
                    tz_data,
                    tz_segments,
                    ERROR_ROUTER_VADDR,
                    sum(ERROR_ROUTER_BANK_SIZES) * 2,
                )
            ),
            "relevant_routes": relevant_error_routes,
            "global_status_sources": [
                {
                    "bank0": "0x01fc2000",
                    "bank1": "0x01fc2004",
                    "masks": ["0xffffffff", "0x0007ffff"],
                },
                {
                    "bank0": "0x01fc4000",
                    "bank1": "0x01fc4004",
                    "masks": ["0xffffffff", "0x0007ffff"],
                },
            ],
            "error_strings_verified": xpu_strings,
        },
        "devcfg_xpu_control": {
            key: (
                f"0x{value:x}"
                if key.endswith("vaddr")
                or key in {"device_hash", "property_offset", "end_marker"}
                else value
            )
            for key, value in devcfg.items()
        },
        "trustzone_code": code,
        "comparative_source": COMPARATIVE_SOURCE,
        "retained_boot_boundary": {
            "non_secure_watchdog_occurrences": watchdog_count,
            "xpu_reporter_start_occurrences": xpu_report_count,
            "encrypted_or_unparsed_tz_log_occurrences": xpu_unparsed_count,
            "decoded_xpu_syndrome": None,
        },
        "claims": {
            "PROVED": [
                (
                    "The exact TZ registry is a 48-record table consumed by "
                    "the pinned HAL lookup function."
                ),
                (
                    "Both exact TZ selector branches configure "
                    "DC_NOC_BROADCAST_MPU with a 40-region table."
                ),
                (
                    "Both branches contain the identical TZ-owned region 11 "
                    "covering 0x09248000-0x09249000, including the tested "
                    "0x09248080 address."
                ),
                (
                    "The exact MPU conversion path turns that record into "
                    "zero standard VMID permission words and "
                    "client-permission bytes 0x11/0x08."
                ),
                (
                    "That conversion grants the TZ owner read/write and the "
                    "MSA-class client read-only, while the static record "
                    "grants no HLOS VMID read or write permission."
                ),
                "The exact devcfg property /ac/xpu:disable_xpu_ac is uint32 value 0.",
                (
                    "The exact TZ error router maps DC_NOC_BROADCAST_MPU, "
                    "MEMNOC_MS_MPU, and all four BIMC_MPU instances to global "
                    "XPU interrupt bits."
                ),
                "Neither embedded TZ static policy list contains BIMC_MPU0..3 descriptors.",
            ],
            "SUPPORTED": [
                (
                    "The fixed EL1 load is strongly compatible with an active "
                    "XPU/fabric access denial rather than a powered-off whole "
                    "LLCC fabric."
                ),
                (
                    "The normal production boot path applies the embedded "
                    "DC_NOC_BROADCAST_MPU policy; the exact devcfg does not "
                    "request XPU disable and boot code calls the static-config "
                    "loop."
                ),
            ],
            "HYPOTHESIS": [
                (
                    "The XPU denial or its downstream interconnect response "
                    "caused the retained Non Secure Watchdog Bark after "
                    "__ioremap returned."
                ),
            ],
            "REFUTED": [
                "The tested address lies outside every exact TZ XPU policy region.",
                (
                    "The critical raw access value is 0x80; it is actually "
                    "little-endian uint32 0x80000000."
                ),
                "The critical static policy grants ordinary HLOS VMID access.",
            ],
            "UNKNOWN": [
                "A post-boot hardware register readback proving the final programmed XPU state.",
                (
                    "A decoded syndrome tying the retained watchdog "
                    "specifically to DC_NOC_BROADCAST_MPU; Samsung's collector "
                    "retained only an encrypted or unparsed TZ log."
                ),
                "Whether a separate clock or power condition contributed to the watchdog response.",
                (
                    "Who initializes BIMC_MPU0..3 on this exact boot and what "
                    "their final policies are."
                ),
                "Protection ordering relative to the final DRAM channel/bank/row transform.",
                "Any normal-RAM physical-to-DRAM alias or protected-memory bypass.",
            ],
        },
        "root_cause_assessment": {
            "evidence_for_xpu_denial": [
                "Exact policy coverage of the tested address",
                "TZ ownership with no HLOS grant",
                "Exact boot static-config call path",
                "disable_xpu_ac=0",
                "Exact XPU error route for the protecting block",
                "Successful __ioremap followed by watchdog before the load returned",
            ],
            "evidence_against_xpu_denial": [
                "No decoded XPU syndrome and no post-boot XPU register readback"
            ],
            "critical_unknowns": [
                "Final runtime policy registers",
                "Exact watchdog fault-response chain",
                "Sub-aperture clock state",
            ],
            "current_status": "SUPPORTED_NOT_PROVED_CAUSAL",
        },
        "classification": "CLASS_A_OR_B_SECURITY_POLICY_PRESENT_NO_BYPASS_OBSERVED",
    }


def inventory(
    tz_path: Path,
    devcfg_path: Path,
    boot_log_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    paths = {
        "trustzone": tz_path,
        "devcfg": devcfg_path,
        "retained_boot_log": boot_log_path,
    }
    data = {label: path.read_bytes() for label, path in paths.items()}
    inputs: dict[str, object] = {}
    private_inputs: dict[str, object] = {}
    for label, path in paths.items():
        metadata = verify_pinned_bytes(label, data[label], PINS[label])
        inputs[label] = {"filename": path.name, **metadata}
        private_inputs[label] = {
            "path": str(path.resolve()),
            "filename": path.name,
            **metadata,
        }

    analysis = analyze(
        data["trustzone"], data["devcfg"], data["retained_boot_log"]
    )
    common = {
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        **analysis,
    }
    private_result = {
        "schema": "sdm855-xpu-policy-inventory-private-v1",
        "inputs": private_inputs,
        **copy.deepcopy(common),
    }
    public_result = {
        "schema": "sdm855-xpu-policy-inventory-public-v1",
        "inputs": inputs,
        **copy.deepcopy(common),
    }
    return private_result, public_result


def atomic_replace(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(temporary)
    write_new(temporary, data, mode)
    os.replace(temporary, path)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    firmware = root / "evidence/private/004-live-firmware-readonly-20260825-01"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tz", type=Path, default=firmware / "tz--sdd5.bin")
    parser.add_argument(
        "--devcfg", type=Path, default=firmware / "devcfg--sdd22.bin"
    )
    parser.add_argument(
        "--boot-log",
        type=Path,
        default=root
        / "evidence/private/007-inline-remapper-read-live-20260825-01.last_kmsg.bin",
    )
    parser.add_argument(
        "--private-output",
        type=Path,
        default=root / "evidence/private/009-xpu-policy-inventory-20260825-01.json",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=root
        / "evidence/manifests/009-xpu-policy-inventory-20260825-01.manifest.json",
    )
    parser.add_argument(
        "--replace", action="store_true", help="atomically replace both outputs"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    private_output = args.private_output.resolve()
    manifest_output = args.manifest_output.resolve()
    if not args.replace:
        for output in (private_output, manifest_output):
            if output.exists():
                raise FileExistsError(output)

    private_result, public_result = inventory(
        args.tz.resolve(), args.devcfg.resolve(), args.boot_log.resolve()
    )
    private_encoded = json_bytes(private_result)
    public_result["private_record"] = {
        "filename": private_output.name,
        "size": len(private_encoded),
        "sha256": sha256(private_encoded),
        "git_ignored": True,
    }
    manifest_encoded = json_bytes(public_result)

    if args.replace:
        atomic_replace(private_output, private_encoded, 0o600)
        atomic_replace(manifest_output, manifest_encoded, 0o644)
    else:
        private_output.parent.mkdir(parents=True, exist_ok=True)
        manifest_output.parent.mkdir(parents=True, exist_ok=True)
        write_new(private_output, private_encoded, 0o600)
        write_new(manifest_output, manifest_encoded, 0o644)
    print(private_output)
    print(manifest_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
