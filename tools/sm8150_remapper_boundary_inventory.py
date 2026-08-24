#!/usr/bin/env python3
"""Recombine exact A90 boot, XBL, DCB and TrustZone remapper evidence.

This is a host-only parser.  It performs no device access and emits no
proprietary firmware bytes.  All four inputs are pinned by size and SHA-256 so
the conclusions cannot silently drift to a different target build.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import re
import struct
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools.xbl_dcb_inventory import LoadSegment, parse_elf64_load_segments
    from tools.xbl_memory_pipeline_inventory import (
        PHYSICAL_PLATFORM_RUMI_VALUE,
        all_bytes_offsets,
        file_offset_to_vaddr,
        inventory_dcb_descriptors,
        parse_icb_property,
        parse_remapper_table,
        read_vaddr,
        unique_bytes_offset,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from xbl_dcb_inventory import LoadSegment, parse_elf64_load_segments
    from xbl_memory_pipeline_inventory import (
        PHYSICAL_PLATFORM_RUMI_VALUE,
        all_bytes_offsets,
        file_offset_to_vaddr,
        inventory_dcb_descriptors,
        parse_icb_property,
        parse_remapper_table,
        read_vaddr,
        unique_bytes_offset,
    )


PINS: Mapping[str, Mapping[str, object]] = {
    "xbl": {
        "size": 4_194_304,
        "sha256": "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37",
    },
    "xbl_config": {
        "size": 4_149_248,
        "sha256": "0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c",
    },
    "trustzone": {
        "size": 4_194_304,
        "sha256": "a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab",
    },
    "retained_boot_log": {
        "size": 2_097_136,
        "sha256": "8701d073e86728790c33f05dce21891ca3454f5b778d92285ce3b5bc33216b93",
    },
}

CHIP_REVISION_RE = re.compile(
    rb"Chip Revision @ 0x01fc8000 = 0x([0-9A-Fa-f]{8})"
)
CDT_RE = re.compile(
    rb"CDT Version:(\d+),Platform ID:(\d+),Major ID:(\d+),"
    rb"Minor ID:(\d+),Subtype:(\d+)"
)
RANK_SIZE_RE = re.compile(
    rb"Rank 0 size = (\d+) MB, Rank 1 size = (\d+) MB"
)

EXPECTED_SELECTED_DCB = {
    "name": "/6003_0200_1_dcb.bin",
    "dcb_sha256": "34caf815065e5fe3e80483e5348a59caa9dc249faa72d97e6e44f818d17ef607",
    "used_size": 11_820,
    "dsf_version": "0x00650000",
    "section16_size": 560,
    "section16_sha256": (
        "cdacfa45183be71c13884ed60dd883a7f94ba5fd4fb9cc92899fac4eb0298dc0"
    ),
}

EXPECTED_REMAPPER_BASES = (
    0x09248080,
    0x092C8080,
    0x09348080,
    0x093C8080,
)

XPU_REGISTRY_EXPECTED: Mapping[str, tuple[int, int]] = {
    "BIMC_MPU0": (0x2E, 0x0924E000),
    "BIMC_MPU1": (0x2F, 0x092CE000),
    "BIMC_MPU2": (0x3F, 0x0934E000),
    "BIMC_MPU3": (0x40, 0x093CE000),
    "MEMNOC_MS_MPU": (0x4B, 0x096C0000),
    "LLCC_BROADCAST_MPU": (0x3A, 0x0964E000),
    "DC_NOC_SHRM_MPU": (0x4D, 0x09102000),
}

FUNCTION_FINGERPRINTS: Mapping[str, Mapping[str, object]] = {
    "ddr_config_producer": {
        "start": 0x14839624,
        "end": 0x14839710,
        "sha256": "bd0e6546c7337e3001b8b26e832df1a655641e264af17314983bb23e348b5420",
    },
    "ddr_config_rank_merge": {
        "start": 0x14839710,
        "end": 0x148397C8,
        "sha256": "11412dae846752db8912fb03434362a822ccec59f5129339ab690623fcc3c09f",
    },
    "remapper_selector": {
        "start": 0x1483A6DC,
        "end": 0x1483A928,
        "sha256": "88eb21c83a091be7847539514240eb8381f323ef42d429c9c3d397d4c2ed82b5",
    },
    "layout1_commit": {
        "start": 0x1484FBBC,
        "end": 0x1484FE74,
        "sha256": "9b3e6deecdddc5cc1fcb7d3ea77d9f7c32409944e1ec49f8f249d7f54aa0719d",
    },
    "icb_set_region": {
        "start": 0x14850694,
        "end": 0x14850A7C,
        "sha256": "d232cbf64098fb72c4d2e8cf7655ba6df5eaef0cf78127cb6a1f33a1df2413a1",
    },
}

PINNED_LAYOUT1_INSTRUCTIONS: Mapping[int, int] = {
    0x1484FBF4: 0xF86E590A,
    0x1484FC00: 0x110005CE,
    0x1484FC44: 0x120001A2,
    0x1484FC50: 0x331C1402,
    0x1484FC54: 0xB90001C2,
    0x1484FC80: 0xB9000DC1,
    0x1484FC9C: 0xB9001223,
    0x1484FCC0: 0xB90005D1,
    0x1484FCDC: 0xB9000A24,
    0x1484FD18: 0x121C1585,
    0x1484FD1C: 0x320000A6,
    0x1484FD20: 0xB9000166,
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


def _one_repeated_value(label: str, values: Sequence[object]) -> object:
    if not values:
        raise ValueError(f"{label} is absent from the retained boot log")
    unique = set(values)
    if len(unique) != 1:
        raise ValueError(f"{label} has conflicting retained values: {sorted(unique)!r}")
    return values[0]


def parse_boot_evidence(data: bytes) -> dict[str, object]:
    chip_values = [int(match, 16) for match in CHIP_REVISION_RE.findall(data)]
    cdt_values = [
        tuple(int(field) for field in match) for match in CDT_RE.findall(data)
    ]
    rank_values = [
        tuple(int(field) for field in match) for match in RANK_SIZE_RE.findall(data)
    ]
    chip_revision = int(_one_repeated_value("chip revision", chip_values))
    cdt = tuple(_one_repeated_value("CDT identity", cdt_values))
    rank0_mib, rank1_mib = tuple(
        _one_repeated_value("rank topology", rank_values)
    )

    cdt_version, platform_id, major_id, minor_id, subtype = cdt
    hardware_id = chip_revision >> 16
    hardware_version = chip_revision & 0xFF00
    physical_platform = int(platform_id != PHYSICAL_PLATFORM_RUMI_VALUE)
    selected_dcb_name = (
        f"/{hardware_id:04X}_{hardware_version:04X}_{physical_platform:d}_dcb.bin"
    )
    rank_mask = int(rank0_mib > 0) | (int(rank1_mib > 0) << 1)

    xpu_report = data.find(b"print_xpu_info: START")
    xpu_unparsed_nearby = False
    if xpu_report >= 0:
        xpu_unparsed_nearby = (
            data.find(
                b"tz log is encrypted or not parsed yet!",
                xpu_report,
                xpu_report + 256,
            )
            >= 0
        )

    return {
        "chip_revision": {
            "register": "0x01fc8000",
            "value": f"0x{chip_revision:08x}",
            "occurrences": len(chip_values),
            "all_occurrences_consistent": True,
        },
        "cdt": {
            "version": cdt_version,
            "platform_id": platform_id,
            "major_id": major_id,
            "minor_id": minor_id,
            "subtype": subtype,
            "occurrences": len(cdt_values),
            "all_occurrences_consistent": True,
        },
        "dcb_selector": {
            "hardware_id": f"0x{hardware_id:04x}",
            "hardware_version": f"0x{hardware_version:04x}",
            "physical_platform": physical_platform,
            "physical_platform_rule": (
                f"1 because platform_id 0x{platform_id:x} != "
                f"RUMI 0x{PHYSICAL_PLATFORM_RUMI_VALUE:x}"
            ),
            "selected_name": selected_dcb_name,
        },
        "dram_topology": {
            "rank0_mib": rank0_mib,
            "rank1_mib": rank1_mib,
            "total_mib": rank0_mib + rank1_mib,
            "present_rank_mask": f"0x{rank_mask:x}",
            "occurrences": len(rank_values),
            "all_occurrences_consistent": True,
        },
        "post_boot_fabric_evidence": {
            "llcc_pmu_registration_occurrences": data.count(b"Registered llcc_pmu"),
            "cpu_llcc_ddr_bwmon_registration_occurrences": data.count(
                b"cpu-llcc-ddr-bwmon: BW HWmon governor registered"
            ),
            "cpu0_llcc_ddr_latmon_registration_occurrences": data.count(
                b"cpu0-llcc-ddr-latmon: Memory Latency governor registered"
            ),
            "cpu4_llcc_ddr_latmon_registration_occurrences": data.count(
                b"cpu4-llcc-ddr-latmon: Memory Latency governor registered"
            ),
            "non_secure_watchdog_string_occurrences": data.count(
                b"Non Secure Watchdog Bark"
            ),
            "xpu_reporter_started": xpu_report >= 0,
            "xpu_report_encrypted_or_unparsed": xpu_unparsed_nearby,
            "xpu_fault_decoding_status": "UNKNOWN_ENCRYPTED_OR_UNPARSED",
        },
    }


def select_dcb_entry(
    entries: Sequence[Mapping[str, object]], selected_name: str
) -> dict[str, object]:
    matches = [dict(entry) for entry in entries if entry["name"] == selected_name]
    if len(matches) != 1:
        raise ValueError(
            f"expected one DCB named {selected_name!r}, found {len(matches)}"
        )
    return matches[0]


def validate_exact_selected_dcb(entry: Mapping[str, object]) -> None:
    section16 = entry["section16"]
    if not isinstance(section16, Mapping):
        raise ValueError("selected DCB section16 metadata is malformed")
    observed = {
        "name": entry["name"],
        "dcb_sha256": entry["dcb_sha256"],
        "used_size": entry["used_size"],
        "dsf_version": entry["dsf_version"],
        "section16_size": section16["size"],
        "section16_sha256": section16["sha256"],
    }
    if observed != EXPECTED_SELECTED_DCB:
        raise ValueError(f"selected DCB pin mismatch: {observed!r}")


def select_remapper_row(
    entries: Sequence[Mapping[str, object]], rank_mask: int, total_mib: int
) -> dict[str, object]:
    matches = [
        dict(entry)
        for entry in entries
        if int(str(entry["channel_rank_mask"]), 0) == rank_mask
        and int(entry["total_mib"]) == total_mib
    ]
    if len(matches) != 1:
        raise ValueError(
            "expected one remapper row for "
            f"rank_mask=0x{rank_mask:x} total_mib={total_mib}, found {len(matches)}"
        )
    return matches[0]


def layout1_register_schema(slot_count: int = 6) -> list[dict[str, object]]:
    if slot_count < 1:
        raise ValueError("slot count must be positive")
    records: list[dict[str, object]] = [
        {
            "offset": "0x00",
            "role": "control",
            "width_bits": 32,
            "fields": {"enable": "bit 0", "active_slot_mask": "bits 9:4"},
        },
        {
            "offset": "0x04",
            "role": "slot0_end_low32",
            "width_bits": 32,
        },
        {
            "offset": "0x08",
            "role": "slot0_end_high4",
            "width_bits": 32,
            "stored_value_mask": "0x0000000f",
            "implicit_slot_start": "0x0",
        },
    ]
    for slot in range(1, slot_count):
        base = 0x0C + (slot - 1) * 0x10
        for delta, suffix in (
            (0x00, "start_low32"),
            (0x04, "start_high4"),
            (0x08, "end_low32"),
            (0x0C, "end_high4"),
        ):
            record: dict[str, object] = {
                "offset": f"0x{base + delta:02x}",
                "role": f"slot{slot}_{suffix}",
                "width_bits": 32,
            }
            if suffix.endswith("high4"):
                record["stored_value_mask"] = "0x0000000f"
            records.append(record)
    return records


def parse_tz_xpu_registry(
    data: bytes,
    segments: Sequence[LoadSegment],
    names: Sequence[str] | None = None,
) -> list[dict[str, object]]:
    selected_names = tuple(names) if names is not None else tuple(XPU_REGISTRY_EXPECTED)
    records: list[dict[str, object]] = []
    for name in selected_names:
        encoded = name.encode("ascii") + b"\0"
        string_file_offset = unique_bytes_offset(data, encoded)
        string_vaddr = file_offset_to_vaddr(
            segments, string_file_offset, len(encoded)
        )
        pointer = struct.pack("<Q", string_vaddr)
        candidates: list[tuple[int, int, int, int]] = []
        for xref in all_bytes_offsets(data, pointer):
            record_file_offset = xref - 16
            if record_file_offset < 0:
                continue
            try:
                record_vaddr = file_offset_to_vaddr(
                    segments, record_file_offset, 24
                )
            except ValueError:
                continue
            resource_id, base, name_pointer = struct.unpack_from(
                "<QQQ", data, record_file_offset
            )
            if name_pointer != string_vaddr:
                continue
            if resource_id >= 0x100:
                continue
            if base == 0 or base >= (1 << 32) or base & 0xFFF:
                continue
            candidates.append((record_vaddr, resource_id, base, xref))
        if len(candidates) != 1:
            raise ValueError(
                f"expected one primary XPU registry record for {name}, "
                f"found {len(candidates)}"
            )
        record_vaddr, resource_id, base, xref = candidates[0]
        if name in XPU_REGISTRY_EXPECTED:
            expected_id, expected_base = XPU_REGISTRY_EXPECTED[name]
            if (resource_id, base) != (expected_id, expected_base):
                raise ValueError(
                    f"{name} registry mismatch: id=0x{resource_id:x} "
                    f"base=0x{base:x}"
                )
        records.append(
            {
                "name": name,
                "resource_id": f"0x{resource_id:x}",
                "base": f"0x{base:08x}",
                "record_virtual_address": f"0x{record_vaddr:x}",
                "name_virtual_address": f"0x{string_vaddr:x}",
                "name_pointer_xref_file_offset": f"0x{xref:x}",
                "record_format": "<uint64 id, uint64 base, uint64 name_pointer>",
            }
        )
    return records


def verify_xbl_functions(
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
                f"XBL function {name} hash mismatch: {digest} != {expected['sha256']}"
            )
        functions[name] = {
            "start": f"0x{start:x}",
            "end_exclusive": f"0x{end:x}",
            "size": end - start,
            "sha256": digest,
        }

    instruction_words: list[dict[str, object]] = []
    for address, expected_word in PINNED_LAYOUT1_INSTRUCTIONS.items():
        word = struct.unpack("<I", read_vaddr(data, segments, address, 4))[0]
        if word != expected_word:
            raise ValueError(
                f"XBL instruction mismatch at 0x{address:x}: "
                f"0x{word:08x} != 0x{expected_word:08x}"
            )
        instruction_words.append(
            {"address": f"0x{address:x}", "word": f"0x{word:08x}"}
        )
    return {
        "functions": functions,
        "layout1_pinned_instruction_words": instruction_words,
    }


def crosscheck_trustzone_function_bytes(
    xbl_data: bytes, xbl_segments: Sequence[LoadSegment], tz_data: bytes
) -> dict[str, object]:
    records: dict[str, object] = {}
    for name, expected in FUNCTION_FINGERPRINTS.items():
        start = int(expected["start"])
        end = int(expected["end"])
        block = read_vaddr(xbl_data, xbl_segments, start, end - start)
        records[name] = {
            "full_body_size": len(block),
            "exact_full_body_occurrences_in_tz": len(all_bytes_offsets(tz_data, block)),
            "exact_first_64_bytes_occurrences_in_tz": len(
                all_bytes_offsets(tz_data, block[:64])
            ),
        }
    return {
        "comparisons": records,
        "claim_boundary": (
            "PROVED no byte-identical XBL function body or 64-byte prefix in "
            "the exact TZ image; semantic equivalents and runtime invocation UNKNOWN"
        ),
    }


def build_same_bank_map(
    remapper_bases: Sequence[int], xpu_records: Sequence[Mapping[str, object]]
) -> list[dict[str, object]]:
    xpu_by_name = {str(record["name"]): record for record in xpu_records}
    result = []
    for index, remapper in enumerate(remapper_bases):
        name = f"BIMC_MPU{index}"
        xpu = xpu_by_name[name]
        xpu_base = int(str(xpu["base"]), 0)
        qhs_llcc_base = remapper & ~0xFFFF
        if xpu_base & ~0xFFFF != qhs_llcc_base:
            raise ValueError(f"{name} is not in the matching qhs_llcc window")
        result.append(
            {
                "instance": index,
                "qhs_llcc_window": f"0x{qhs_llcc_base:08x}",
                "remapper": {
                    "base": f"0x{remapper:08x}",
                    "window_offset": "0x8080",
                },
                "bimc_mpu": {
                    "name": name,
                    "resource_id": xpu["resource_id"],
                    "base": f"0x{xpu_base:08x}",
                    "window_offset": "0xe000",
                },
                "config_aperture_delta": "0x5f80",
            }
        )
    return result


def analyze(
    xbl_data: bytes,
    xbl_config_data: bytes,
    tz_data: bytes,
    boot_log_data: bytes,
) -> dict[str, object]:
    boot = parse_boot_evidence(boot_log_data)
    xbl_segments = parse_elf64_load_segments(xbl_data)
    tz_segments = parse_elf64_load_segments(tz_data)

    dcb_inventory = inventory_dcb_descriptors(xbl_config_data)
    selected_name = str(boot["dcb_selector"]["selected_name"])
    selected_dcb = select_dcb_entry(dcb_inventory["entries"], selected_name)
    validate_exact_selected_dcb(selected_dcb)

    remapper_entries = parse_remapper_table(xbl_data, xbl_segments)
    topology = boot["dram_topology"]
    selected_row = select_remapper_row(
        remapper_entries,
        int(str(topology["present_rank_mask"]), 0),
        int(topology["total_mib"]),
    )
    if selected_row["index"] != 7:
        raise ValueError(f"unexpected selected remapper row {selected_row['index']}")

    icb = parse_icb_property(xbl_data, xbl_segments)
    if len(icb["records"]) != 1:
        raise ValueError("expected the exact XBL to contain one ICB chip record")
    icb_record = icb["records"][0]
    remapper_bases = tuple(
        int(str(item["address"]), 0) for item in icb_record["register_bases"]
    )
    if remapper_bases != EXPECTED_REMAPPER_BASES:
        raise ValueError(f"unexpected remapper base tuple {remapper_bases!r}")
    expected_layout = (6, 4, 36, 1)
    observed_layout = (
        icb_record["mapping_slot_count"],
        icb_record["channel_instance_count"],
        icb_record["table_entry_count"],
        icb_record["register_layout"],
    )
    if observed_layout != expected_layout:
        raise ValueError(f"unexpected ICB layout {observed_layout!r}")

    xpu_records = parse_tz_xpu_registry(tz_data, tz_segments)
    functions = verify_xbl_functions(xbl_data, xbl_segments)
    tz_code_crosscheck = crosscheck_trustzone_function_bytes(
        xbl_data, xbl_segments, tz_data
    )
    same_bank = build_same_bank_map(remapper_bases, xpu_records)
    register_schema = layout1_register_schema(6)

    return {
        "boot_evidence": boot,
        "selected_dcb": selected_dcb,
        "selected_remapper_row": selected_row,
        "special_12g_case": {
            "xbl_predicate": (
                "rank0_total_mib == 4096 AND rank1_total_mib == 8192 "
                "AND processing rank1"
            ),
            "selected_boot_matches": False,
            "status": "REFUTED_FOR_THIS_BOOT",
        },
        "xbl_writer": {
            **functions,
            "icb_device": "/dev/icbcfg/boot",
            "icb_property": "icbcfg_info",
            "trustzone_code_crosscheck": tz_code_crosscheck,
            "layout": {
                "layout_id": 1,
                "instance_count": 4,
                "slot_count": 6,
                "register_access_width_bits": 32,
                "encoded_address_width_bits": 36,
                "registers": register_schema,
                "writer_order": [
                    "For each instance, read control +0x00 and write old_control & 0x3f0.",
                    "Write slot 0 end and slots 1..5 start/end as low32 plus high4.",
                    "Write active-slot mask into control bits 9:4.",
                    "For each instance, write (control & 0x3f0) | 1 to enable.",
                ],
                "lock_write_boundary": (
                    "PROVED only within 0x1484fbbc..0x1484fe74: no distinct "
                    "lock-register write; later firmware or hardware lock UNKNOWN"
                ),
            },
        },
        "runtime_ddr_dependencies": {
            "producer_function": "0x14839624",
            "producer_output": {
                "virtual_address": "0x1488bc98",
                "size": "0xd0",
            },
            "per_channel_runtime_context": {
                "rank0_size_mib": "context + 0x158 + 4*i",
                "rank1_size_mib": "context + 0x178 + 4*i",
                "rank0_source_base": "context + 0x1a8 + 8*i",
                "rank1_source_base": "context + 0x1e8 + 8*i",
            },
            "rank_interleave_mask": {
                "producer": "function 0x148390f0",
                "config_offset": "0xc8",
            },
            "rank_merge_function": "0x14839710",
            "rank_merge_output": {
                "virtual_address": "0x1488bd68",
                "size": "0xc8",
            },
            "region_arguments": [
                {
                    "rank": 0,
                    "source_base": "UNKNOWN_RUNTIME_CONTEXT_0x1a8",
                    "size_mib": topology["rank0_mib"],
                    "destination_base": selected_row["region0_base"],
                },
                {
                    "rank": 1,
                    "source_base": "UNKNOWN_RUNTIME_CONTEXT_0x1e8",
                    "size_mib": topology["rank1_mib"],
                    "destination_base": selected_row["region1_base"],
                },
            ],
            "numeric_boot_register_values": {
                "status": "UNKNOWN_DEPENDS_ON_RUNTIME_DDR_CONTEXT",
                "missing_inputs": [
                    "per-channel rank source bases",
                    "rank interleave mask",
                ],
                "do_not_guess": True,
            },
        },
        "trustzone_xpu_registry": xpu_records,
        "same_qhs_llcc_bank_relationship": same_bank,
        "claims": {
            "PROVED": [
                "All inputs match the exact retained A90 artifact size and SHA-256 pins.",
                "The retained XBL log consistently selects /6003_0200_1_dcb.bin.",
                "The selected DCB and its 560-byte section 16 match exact hashes.",
                "The retained 3072+3072 MiB topology uniquely selects remapper row 7.",
                "XBL's exact layout-1 writer programs four 36-bit, six-slot windows through 32-bit MMIO fields.",
                "The exact layout-1 writer contains no distinct lock-register write within its bounded function range.",
                "TrustZone's primary XPU registry binds BIMC_MPU0..3 to qhs_llcc+0xe000 in the same four windows as remapper+0x8080.",
                "The exact TrustZone image contains no byte-identical copy of the five pinned XBL functions or their first 64 bytes.",
                "Successful retained boots register LLCC PMU and LLCC-to-DDR monitoring endpoints.",
            ],
            "SUPPORTED": [
                "A whole-fabric power-off explanation is disfavored; the +0x8080 sub-aperture may still have separate power, clock, or security behavior.",
                "TrustZone has explicit configuration knowledge of protection blocks in each remapper's qhs_llcc instance.",
            ],
            "HYPOTHESIS": [
                "The post-boot +0x8080 watchdog may be caused by sub-aperture security ownership, clock gating, or a fabric fault response; these alternatives remain distinguishable only with further static evidence.",
            ],
            "REFUTED": [
                "The exact live DCB selector revision remains unknown.",
                "XBL's special 12-GiB remap predicate applies to this 6-GiB boot.",
            ],
            "UNKNOWN": [
                "Exact numeric boot values because runtime per-channel source bases and the interleave mask were not captured.",
                "Whether BIMC_MPU0..3 protect the +0x8080 configuration aperture, downstream transactions, or both.",
                "Whether TrustZone invokes the matching icbcfg record or programs a later lock.",
                "Whether the fixed read watchdog was an access denial, clock/power condition, or another interconnect fault.",
                "The retained TZ/XPU diagnostic payload is encrypted or unparsed, so absence of a decoded XPU violation is not exculpatory.",
                "Protection ordering relative to final DRAM channel/bank/row decode.",
                "Any normal-RAM physical-to-DRAM alias or protected-boundary bypass.",
            ],
        },
        "classification": "NO_BOUNDARY_BYPASS_OBSERVED_CLASS_UNKNOWN",
    }


def inventory(
    xbl_path: Path,
    xbl_config_path: Path,
    tz_path: Path,
    boot_log_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    paths = {
        "xbl": xbl_path,
        "xbl_config": xbl_config_path,
        "trustzone": tz_path,
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
        data["xbl"],
        data["xbl_config"],
        data["trustzone"],
        data["retained_boot_log"],
    )
    common = {
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        **analysis,
    }
    private_result = {
        "schema": "sdm855-remapper-boundary-inventory-private-v1",
        "inputs": private_inputs,
        **copy.deepcopy(common),
    }
    public_result = {
        "schema": "sdm855-remapper-boundary-inventory-public-v1",
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
    parser.add_argument("--xbl", type=Path, default=firmware / "xbl--sdb1.bin")
    parser.add_argument(
        "--xbl-config", type=Path, default=firmware / "xbl_config--sdb2.bin"
    )
    parser.add_argument("--tz", type=Path, default=firmware / "tz--sdd5.bin")
    parser.add_argument(
        "--boot-log",
        type=Path,
        default=root
        / "evidence/private/007-inline-remapper-read-live-20260825-01.last_kmsg.bin",
    )
    parser.add_argument(
        "--private-output",
        type=Path,
        default=root
        / "evidence/private/008-remapper-boundary-inventory-20260825-01.json",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=root
        / "evidence/manifests/008-remapper-boundary-inventory-20260825-01.manifest.json",
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
        args.xbl.resolve(),
        args.xbl_config.resolve(),
        args.tz.resolve(),
        args.boot_log.resolve(),
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
