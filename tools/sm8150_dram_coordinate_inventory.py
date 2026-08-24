#!/usr/bin/env python3
"""Recover the exact A90 XBL DDR diagnostic coordinate map and SHRM lists.

This is a host-only parser.  It performs no device, SMC, or MMIO access and
emits no proprietary firmware bytes.  The exact XBL, XBL configuration, and
retained boot log are pinned by size and SHA-256.

The recovered rank/row/bank/channel/column formula is the formula used by the
exact XBL Quest DDR failure reporter.  It is not silently promoted to proof
that no additional transform exists in silicon.
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
    from tools.sm8150_remapper_boundary_inventory import (
        parse_boot_evidence,
        select_remapper_row,
        verify_pinned_bytes,
    )
    from tools.xbl_dcb_inventory import parse_dcb, parse_elf64_load_segments
    from tools.xbl_memory_pipeline_inventory import (
        file_offset_to_vaddr,
        parse_cfgl,
        parse_remapper_table,
        read_c_string_vaddr,
        read_vaddr,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from sm8150_remapper_boundary_inventory import (
        parse_boot_evidence,
        select_remapper_row,
        verify_pinned_bytes,
    )
    from xbl_dcb_inventory import parse_dcb, parse_elf64_load_segments
    from xbl_memory_pipeline_inventory import (
        file_offset_to_vaddr,
        parse_cfgl,
        parse_remapper_table,
        read_c_string_vaddr,
        read_vaddr,
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
    "retained_boot_log": {
        "size": 2_097_136,
        "sha256": "8701d073e86728790c33f05dce21891ca3454f5b778d92285ce3b5bc33216b93",
    },
}

SELECTED_DCB_NAME = "/6003_0200_1_dcb.bin"
SELECTED_DCB_SHA256 = (
    "34caf815065e5fe3e80483e5348a59caa9dc249faa72d97e6e44f818d17ef607"
)
SECTION16_SHA256 = (
    "cdacfa45183be71c13884ed60dd883a7f94ba5fd4fb9cc92899fac4eb0298dc0"
)

SYSTEM_DRAM_BASE = 0x80000000
CURRENT_RANK0_MIB = 3072
CURRENT_RANK1_MIB = 3072
CURRENT_TOTAL_GIB = 6
CURRENT_RANK1_BASE = 0x140000000
CURRENT_DRAM_END_EXCLUSIVE = 0x200000000

FUNCTION_FINGERPRINTS: Mapping[str, tuple[int, int, str]] = {
    "quest_ddr_size_accumulator": (
        0x14921C74,
        0x14921D0C,
        "be35e402bd3e8308bf9847ebd37ef86b9ec88251db6dfd8b682b9e1af01253e8",
    ),
    "quest_ddr_coordinate_reporter": (
        0x149212C0,
        0x149213EC,
        "8231938c0dea131de6b4f0294aa3016017981c2fa85194a864b69ba7ae45e8e0",
    ),
    "quest_ddr_failure_recorder": (
        0x1492234C,
        0x14922428,
        "7aa83eb960e56f5af2619a61e36ea6f47293403b8246d34dd7bc8c4b8d2cbee2",
    ),
}

# These words pin the exact arithmetic sequence without depending on an
# external disassembler at runtime.
PINNED_INSTRUCTION_WORDS: Mapping[int, int] = {
    # DDR-size accumulator feeding the reporter's rank boundary.
    0x14921C80: 0xF900421F,
    0x14921C94: 0xF9400660,
    0x14921CA0: 0xF94008CC,
    0x14921CA4: 0xF86B680A,
    0x14921CAC: 0xD34AAD51,
    0x14921CB0: 0x8B0C0222,
    0x14921CB4: 0xF90008C2,
    0x14921CC8: 0xF9400802,
    # Rank-relative PA and coordinate extraction.
    0x14921304: 0xF9400928,
    0x14921314: 0xD363850B,
    0x14921318: 0x8B09016C,
    0x1492131C: 0x4B0B012D,
    0x14921320: 0xEB14019F,
    0x14921324: 0x9A8D814E,
    0x14921328: 0x1A9F87F5,
    0x1492132C: 0x0B1401C8,
    0x14921330: 0x53037D09,
    0x14921334: 0x12180539,
    0x14921338: 0x53107D16,
    0x1492133C: 0x530D3D17,
    0x14921340: 0x53092918,
    0x14921344: 0x33012119,
    # The real failure recorder invokes the coordinate reporter.
    0x1492236C: 0x97FFFBD5,
    # Both invert_row reports pass a local flag onward in DDR code.
    0x148B95C0: 0x910EE442,
    0x148B95CC: 0x2A1B03E3,
    0x148B95FC: 0x2A1903E3,
    0x148B960C: 0x97FFFD34,
    0x148B9D8C: 0x910EE442,
    0x148B9D98: 0x2A1503E3,
    0x148B9E1C: 0x2A1503E2,
    0x148B9E60: 0x97FFFB1F,
}

COORDINATE_FORMAT_VADDR = 0x14962D18
COORDINATE_FORMAT = (
    "ERR:0x%llx 0x%llx->0x%llx, rank(%d)row(0x%lx)"
    "bank(%d)ch(%d)column(0x%lx)\r\n"
)
INVERT_ROW_FORMAT = b"invert_row: %d\0"

SHRM_TOPOLOGY_RECORD_SIZE = 84
SHRM_TOPOLOGY_RECORD_COUNT = 33
SHRM_TOPOLOGY_START_PATTERN = (
    struct.pack("<II", 0x20, 0) + b"qhm_shrm".ljust(25, b"\0")
)

FOUR_CHANNEL_MCCC_PAGES = (0x9250, 0x92D0, 0x9350, 0x93D0)
FOUR_CHANNEL_MC_PAGES = (0x9260, 0x92E0, 0x9360, 0x93E0)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _one_offset(data: bytes, needle: bytes, label: str) -> int:
    first = data.find(needle)
    if first < 0:
        raise ValueError(f"{label} is absent")
    if data.find(needle, first + 1) >= 0:
        raise ValueError(f"{label} is not unique")
    return first


def verify_xbl_code(data: bytes) -> dict[str, object]:
    segments = parse_elf64_load_segments(data)
    functions: dict[str, object] = {}
    for name, (start, end, expected_hash) in FUNCTION_FINGERPRINTS.items():
        raw = read_vaddr(data, segments, start, end - start)
        actual = sha256(raw)
        if actual != expected_hash:
            raise ValueError(
                f"{name} fingerprint mismatch: {actual} != {expected_hash}"
            )
        functions[name] = {
            "start": f"0x{start:x}",
            "end_exclusive": f"0x{end:x}",
            "size": len(raw),
            "sha256": actual,
        }

    words = []
    for address, expected in PINNED_INSTRUCTION_WORDS.items():
        observed = struct.unpack("<I", read_vaddr(data, segments, address, 4))[0]
        if observed != expected:
            raise ValueError(
                f"instruction mismatch at 0x{address:x}: "
                f"0x{observed:08x} != 0x{expected:08x}"
            )
        words.append({"address": f"0x{address:x}", "word": f"0x{observed:08x}"})

    coordinate_format = read_c_string_vaddr(
        data, segments, COORDINATE_FORMAT_VADDR, 160
    )
    if coordinate_format != COORDINATE_FORMAT:
        raise ValueError("Quest DDR coordinate format string mismatch")

    invert_offset = _one_offset(data, INVERT_ROW_FORMAT, "invert_row format")
    return {
        "functions": functions,
        "instruction_words": words,
        "coordinate_format": {
            "virtual_address": f"0x{COORDINATE_FORMAT_VADDR:x}",
            "sha256": sha256((coordinate_format + "\0").encode("ascii")),
        },
        "invert_row": {
            "file_offset": f"0x{invert_offset:x}",
            "virtual_address": f"0x{file_offset_to_vaddr(segments, invert_offset):x}",
            "occurrences": 1,
            "code_references": ["0x148b95c0", "0x148b9d8c"],
            "local_flag_forwarding_calls": ["0x148b960c", "0x148b9e60"],
            "coordinate_reporter_reference": False,
        },
    }


def extract_selected_section16(
    xbl_config_data: bytes, selected_name: str
) -> tuple[bytes, dict[str, object]]:
    cfgl = parse_cfgl(xbl_config_data)
    matches = [entry for entry in cfgl["entries"] if entry.name == selected_name]
    if len(matches) != 1:
        raise ValueError(f"expected one selected DCB, found {len(matches)}")
    entry = matches[0]
    block = xbl_config_data[
        entry.data_file_offset : entry.data_file_offset + entry.data_size
    ]
    parsed = parse_dcb(block)
    if parsed["sha256"] != SELECTED_DCB_SHA256:
        raise ValueError("selected DCB SHA-256 mismatch")
    section = next(item for item in parsed["sections"] if item["index"] == 16)
    section_offset = int(str(section["data_offset"]), 0)
    raw = block[section_offset : section_offset + int(section["size"])]
    if sha256(raw) != SECTION16_SHA256:
        raise ValueError("selected DCB section 16 SHA-256 mismatch")
    return raw, {
        "name": selected_name,
        "dcb_sha256": parsed["sha256"],
        "dcb_used_size": parsed["used_size"],
        "descriptor_file_offset": f"0x{entry.descriptor_file_offset:x}",
        "payload_file_offset": f"0x{entry.data_file_offset:x}",
        "section16_dcb_offset": f"0x{section_offset:x}",
        "section16_size": len(raw),
        "section16_sha256": sha256(raw),
        "section16_destination": "0x09065100",
    }


def _parse_register_set(
    data: bytes, start: int, end: int, set_index: int
) -> list[dict[str, object]]:
    records = []
    cursor = start
    while cursor < end:
        record_offset = cursor
        if cursor + 2 > end:
            raise ValueError(f"register set {set_index} has a truncated record header")
        base_count, offset_count = struct.unpack_from("<BB", data, cursor)
        cursor += 2
        payload_size = 2 * (base_count + offset_count)
        if cursor + payload_size > end:
            raise ValueError(f"register set {set_index} record crosses its boundary")
        bases = list(
            struct.unpack_from(f"<{base_count}H", data, cursor)
            if base_count
            else ()
        )
        cursor += 2 * base_count
        offsets = list(
            struct.unpack_from(f"<{offset_count}H", data, cursor)
            if offset_count
            else ()
        )
        cursor += 2 * offset_count
        records.append(
            {
                "index": len(records),
                "section_offset": f"0x{record_offset:x}",
                "base_count": base_count,
                "offset_count": offset_count,
                "base_pages": [f"0x{value:04x}" for value in bases],
                "base_addresses_if_4k_pages": [
                    f"0x{value << 12:08x}" for value in bases
                ],
                "offset_tokens": [f"0x{value:04x}" for value in offsets],
                "padding": base_count == 0 and offset_count == 0,
            }
        )
    if cursor != end:
        raise ValueError(f"register set {set_index} did not end exactly")
    return records


def parse_section16_register_sets(data: bytes) -> dict[str, object]:
    if len(data) < 8:
        raise ValueError("section 16 is shorter than its header")
    header_size, total_size, split_offset, unknown_field = struct.unpack_from(
        "<HHHH", data, 0
    )
    if header_size != 8:
        raise ValueError(f"unexpected section 16 header size {header_size}")
    if total_size != len(data):
        raise ValueError(
            f"section 16 total-size mismatch: {total_size} != {len(data)}"
        )
    if not header_size <= split_offset <= total_size:
        raise ValueError("section 16 split offset is outside the payload")
    ranges = ((header_size, split_offset), (split_offset, total_size))
    sets = []
    for index, (start, end) in enumerate(ranges):
        records = _parse_register_set(data, start, end, index)
        sets.append(
            {
                "index": index,
                "start_offset": f"0x{start:x}",
                "end_offset_exclusive": f"0x{end:x}",
                "record_count": len(records),
                "padding_record_count": sum(bool(item["padding"]) for item in records),
                "records": records,
            }
        )
    return {
        "header": {
            "header_size": header_size,
            "total_size": total_size,
            "set_split_offset": f"0x{split_offset:x}",
            "unknown_u16_3": f"0x{unknown_field:04x}",
        },
        "sets": sets,
    }


def _decode_padded_ascii(raw: bytes, label: str) -> str:
    value, separator, padding = raw.partition(b"\0")
    if not separator or any(padding):
        raise ValueError(f"malformed padded ASCII field {label}")
    return value.decode("ascii", errors="strict")


def parse_shrm_topology(data: bytes) -> dict[str, object]:
    start = _one_offset(data, SHRM_TOPOLOGY_START_PATTERN, "SHRM topology start")
    size = SHRM_TOPOLOGY_RECORD_COUNT * SHRM_TOPOLOGY_RECORD_SIZE
    if start + size > len(data):
        raise ValueError("SHRM topology table is truncated")
    raw = data[start : start + size]
    records = []
    for index in range(SHRM_TOPOLOGY_RECORD_COUNT):
        record = raw[
            index * SHRM_TOPOLOGY_RECORD_SIZE :
            (index + 1) * SHRM_TOPOLOGY_RECORD_SIZE
        ]
        group, instance = struct.unpack_from("<II", record, 0)
        master = _decode_padded_ascii(record[8:33], f"master {index}")
        target = _decode_padded_ascii(record[33:65], f"target {index}")
        address_text = _decode_padded_ascii(record[65:84], f"address {index}")
        if master != "qhm_shrm":
            raise ValueError(f"topology record {index} is not owned by qhm_shrm")
        address = None if address_text == "NA" else int(address_text, 0)
        records.append(
            {
                "index": index,
                "group": f"0x{group:x}",
                "instance": instance,
                "master": master,
                "target": target,
                "address": None if address is None else f"0x{address:08x}",
            }
        )

    expected = {
        "qhs_mccc": [0x09250000, 0x092D0000, 0x09350000, 0x093D0000, 0x09650000],
        "qhs_mc": [0x09260000, 0x092E0000, 0x09360000, 0x093E0000, 0x09660000],
        "qhs_mccc_master": [0x090B0000],
        "qhs_shrm_csr": [0x09050000],
        "qhs_ddrss_regs": [0x090C0000],
    }
    bindings: dict[str, object] = {}
    for target, expected_addresses in expected.items():
        observed = [
            int(str(item["address"]), 0)
            for item in records
            if item["target"] == target and item["address"] is not None
        ]
        if observed != expected_addresses:
            raise ValueError(
                f"SHRM topology {target} mismatch: {observed!r} != {expected_addresses!r}"
            )
        bindings[target] = [f"0x{value:08x}" for value in observed]
    return {
        "file_offset": f"0x{start:x}",
        "size": size,
        "sha256": sha256(raw),
        "record_size": SHRM_TOPOLOGY_RECORD_SIZE,
        "record_count": len(records),
        "bindings": bindings,
        "records": records,
    }


def diagnostic_rank1_base(total_gib: int) -> int:
    if total_gib <= 0:
        raise ValueError("total GiB must be positive")
    return SYSTEM_DRAM_BASE + (total_gib << 29)


def diagnostic_coordinate(pa: int, total_gib: int) -> dict[str, int]:
    rank1_base = diagnostic_rank1_base(total_gib)
    if pa < SYSTEM_DRAM_BASE:
        raise ValueError("physical address is below the diagnostic DRAM base")
    if pa < rank1_base:
        rank = 0
        offset = pa - SYSTEM_DRAM_BASE
    else:
        rank = 1
        offset = pa - rank1_base
    if offset > 0xFFFFFFFF:
        raise ValueError("rank-relative offset exceeds the reporter's 32-bit domain")
    return {
        "rank": rank,
        "row": offset >> 16,
        "bank": (offset >> 13) & 0x7,
        "channel": (offset >> 9) & 0x3,
        "column": ((offset >> 1) & 0xFF) | (((offset >> 11) & 0x3) << 8),
        "byte_in_x16": offset & 0x1,
        "rank_relative_offset": offset,
    }


def coordinate_to_pa(
    *,
    rank: int,
    row: int,
    bank: int,
    channel: int,
    column: int,
    byte_in_x16: int,
    total_gib: int,
) -> int:
    limits = {
        "rank": (rank, 1),
        "row": (row, 0xFFFF),
        "bank": (bank, 0x7),
        "channel": (channel, 0x3),
        "column": (column, 0x3FF),
        "byte_in_x16": (byte_in_x16, 0x1),
    }
    for label, (value, maximum) in limits.items():
        if value < 0 or value > maximum:
            raise ValueError(f"{label} is outside 0..0x{maximum:x}")
    offset = (
        (row << 16)
        | (bank << 13)
        | ((column >> 8) << 11)
        | (channel << 9)
        | ((column & 0xFF) << 1)
        | byte_in_x16
    )
    base = SYSTEM_DRAM_BASE if rank == 0 else diagnostic_rank1_base(total_gib)
    return base + offset


def _record_base_pages(record: Mapping[str, object]) -> tuple[int, ...]:
    return tuple(int(str(value), 0) for value in record["base_pages"])


def _candidate_records(
    parsed: Mapping[str, object], predicate
) -> list[dict[str, object]]:
    result = []
    for register_set in parsed["sets"]:
        for record in register_set["records"]:
            if not record["padding"] and predicate(_record_base_pages(record)):
                result.append(
                    {
                        "set_index": register_set["index"],
                        "record_index": record["index"],
                        "section_offset": record["section_offset"],
                        "base_pages": record["base_pages"],
                        "base_addresses_if_4k_pages": record[
                            "base_addresses_if_4k_pages"
                        ],
                        "offset_tokens": record["offset_tokens"],
                    }
                )
    return result


def build_candidate_inventory(parsed: Mapping[str, object]) -> list[dict[str, object]]:
    def four_channel_family(pages: tuple[int, ...], anchors: tuple[int, ...]) -> bool:
        if len(pages) != 4:
            return False
        deltas = tuple(value - anchor for value, anchor in zip(pages, anchors))
        return len(set(deltas)) == 1 and 0 <= deltas[0] <= 0xF

    specs = (
        (
            "per-channel MCCC",
            lambda pages: pages == FOUR_CHANNEL_MCCC_PAGES,
            "qhm_shrm -> qhs_mccc",
        ),
        (
            "per-channel MC pages",
            lambda pages: four_channel_family(pages, FOUR_CHANNEL_MC_PAGES),
            "qhm_shrm -> qhs_mc",
        ),
        (
            "MCCC master",
            lambda pages: pages == (0x90B0,),
            "qhm_shrm -> qhs_mccc_master",
        ),
        (
            "DDRSS registers",
            lambda pages: pages == (0x90C0,),
            "qhm_shrm -> qhs_ddrss_regs",
        ),
        (
            "SHRM CSR",
            lambda pages: pages == (0x9050,),
            "qhm_shrm -> qhs_shrm_csr",
        ),
    )
    result = []
    for rank, (name, predicate, topology_binding) in enumerate(specs, 1):
        records = _candidate_records(parsed, predicate)
        if not records:
            raise ValueError(f"candidate {name} has no section 16 records")
        result.append(
            {
                "rank": rank,
                "name": name,
                "topology_binding": topology_binding,
                "records": records,
                "token_enumeration_status": "PROVED",
                "base_token_as_4k_page_semantics": "SUPPORTED",
                "final_address_transform_semantics": "HYPOTHESIS",
                "offset_token_scaling": "UNKNOWN",
                "write_opcode_and_stage": "UNKNOWN_SHRM_FORMAT_NOT_DECODED",
                "runtime_readability_writability_lock": "UNKNOWN",
            }
        )
    return result


def analyze(
    xbl_data: bytes, xbl_config_data: bytes, boot_log_data: bytes
) -> dict[str, object]:
    boot = parse_boot_evidence(boot_log_data)
    topology = boot["dram_topology"]
    if (
        topology["rank0_mib"] != CURRENT_RANK0_MIB
        or topology["rank1_mib"] != CURRENT_RANK1_MIB
    ):
        raise ValueError("retained rank topology no longer matches the exact target")
    if int(topology["total_mib"]) % 1024:
        raise ValueError("retained total memory is not an integral GiB")
    total_gib = int(topology["total_mib"]) // 1024
    if total_gib != CURRENT_TOTAL_GIB:
        raise ValueError("retained total-GiB value mismatch")

    selected_name = str(boot["dcb_selector"]["selected_name"])
    if selected_name != SELECTED_DCB_NAME:
        raise ValueError(f"unexpected DCB selection {selected_name}")
    section16_raw, selected_dcb = extract_selected_section16(
        xbl_config_data, selected_name
    )
    section16 = parse_section16_register_sets(section16_raw)
    if section16["header"] != {
        "header_size": 8,
        "total_size": 560,
        "set_split_offset": "0x1b8",
        "unknown_u16_3": "0x08e8",
    }:
        raise ValueError("selected section 16 header mismatch")
    if [item["record_count"] for item in section16["sets"]] != [22, 8]:
        raise ValueError("selected section 16 record-count mismatch")
    if [item["padding_record_count"] for item in section16["sets"]] != [2, 1]:
        raise ValueError("selected section 16 padding-count mismatch")

    xbl_segments = parse_elf64_load_segments(xbl_data)
    remapper_rows = parse_remapper_table(xbl_data, xbl_segments)
    selected_row = select_remapper_row(
        remapper_rows,
        int(str(topology["present_rank_mask"]), 0),
        int(topology["total_mib"]),
    )
    rank1_base = diagnostic_rank1_base(total_gib)
    if int(str(selected_row["region0_base"]), 0) != SYSTEM_DRAM_BASE:
        raise ValueError("selected remapper rank-0 base mismatch")
    if int(str(selected_row["region1_base"]), 0) != rank1_base:
        raise ValueError("diagnostic rank boundary and remapper row disagree")
    if rank1_base != CURRENT_RANK1_BASE:
        raise ValueError("current rank-1 base mismatch")
    dram_end = rank1_base + (CURRENT_RANK1_MIB << 20)
    if dram_end != CURRENT_DRAM_END_EXCLUSIVE:
        raise ValueError("current DRAM end mismatch")

    code = verify_xbl_code(xbl_data)
    shrm_topology = parse_shrm_topology(xbl_data)
    topology_vaddr = file_offset_to_vaddr(
        xbl_segments, int(shrm_topology["file_offset"], 0)
    )
    shrm_topology["virtual_address"] = f"0x{topology_vaddr:x}"
    candidates = build_candidate_inventory(section16)

    samples = []
    for pa in (
        SYSTEM_DRAM_BASE,
        SYSTEM_DRAM_BASE + 0x12345678,
        rank1_base - 1,
        rank1_base,
        rank1_base + 0x12345678,
        dram_end - 1,
    ):
        coordinate = diagnostic_coordinate(pa, total_gib)
        round_trip = coordinate_to_pa(
            rank=coordinate["rank"],
            row=coordinate["row"],
            bank=coordinate["bank"],
            channel=coordinate["channel"],
            column=coordinate["column"],
            byte_in_x16=coordinate["byte_in_x16"],
            total_gib=total_gib,
        )
        if round_trip != pa:
            raise ValueError(f"coordinate round trip failed for 0x{pa:x}")
        samples.append(
            {
                "physical_address": f"0x{pa:x}",
                **{
                    key: (
                        f"0x{value:x}"
                        if key in {"row", "column", "rank_relative_offset"}
                        else value
                    )
                    for key, value in coordinate.items()
                },
                "round_trip_physical_address": f"0x{round_trip:x}",
            }
        )

    return {
        "boot_evidence": boot,
        "selected_dcb": selected_dcb,
        "section16_register_sets": section16,
        "shrm_topology": shrm_topology,
        "candidate_controller_register_sets_top5": candidates,
        "xbl_code_evidence": code,
        "diagnostic_coordinate_map": {
            "scope": "EXACT_XBL_QUEST_DDR_FAILURE_REPORTER",
            "system_dram_base": f"0x{SYSTEM_DRAM_BASE:x}",
            "runtime_size_global": "0x85e99090",
            "runtime_size_semantics": (
                "Quest code accumulates range-size fields shifted by 10 and "
                "prints the result as DDR size in GiB"
            ),
            "current_total_gib": total_gib,
            "rank1_boundary_formula": "0x80000000 + (total_gib << 29)",
            "rank0_base": f"0x{SYSTEM_DRAM_BASE:x}",
            "rank1_base": f"0x{rank1_base:x}",
            "dram_end_exclusive": f"0x{dram_end:x}",
            "selected_remapper_row": selected_row,
            "rank_relative_formula": {
                "rank": "0 if PA < rank1_base else 1",
                "offset": "PA - selected rank base, low 32 bits",
                "row": "offset[31:16]",
                "bank": "offset[15:13]",
                "channel": "offset[10:9]",
                "column": "offset[12:11] concatenated with offset[8:1]",
                "byte_in_x16": "offset[0]",
            },
            "bit_partition_is_complete_and_nonoverlapping": True,
            "coordinate_bit_packing_is_bijective_over_32bit_offset": True,
            "current_dram_ranges_are_injective_under_formula": True,
            "xor_or_hash_in_bounded_formula": False,
            "hidden_hardware_transform_excluded": False,
            "samples": samples,
        },
        "protection_ordering": {
            "qhee_stage2_smmu_before_or_after_diagnostic_coordinate_map": "UNKNOWN",
            "tz_bimc_mpu_before_or_after_final_hardware_decode": "UNKNOWN",
            "post_transform_check": "UNKNOWN",
        },
        "claims": {
            "PROVED": [
                "All three inputs match exact retained A90 size and SHA-256 pins.",
                "The retained boot selects the exact 560-byte section 16 of /6003_0200_1_dcb.bin.",
                (
                    "Section 16 parses exactly into two compact "
                    "base-token/offset-token sets with 22 and 8 records."
                ),
                (
                    "Section-16 base tokens numerically equal "
                    "physical-base>>12 for exact per-channel MCCC/MC, "
                    "MCCC-master, DDRSS, and SHRM-CSR qhm_shrm bindings."
                ),
                (
                    "The exact XBL qhm_shrm topology independently binds "
                    "those controller families to the same physical bases."
                ),
                (
                    "The exact Quest DDR failure path calls a pinned "
                    "coordinate reporter that labels rank, row, bank, "
                    "channel, and column."
                ),
                (
                    "For the retained 6-GiB topology its computed rank "
                    "boundary is 0x140000000, exactly remapper row 7's "
                    "rank-1 destination."
                ),
                (
                    "The bounded coordinate formula partitions every one "
                    "of the 32 rank-relative address bits and is "
                    "mathematically bijective."
                ),
            ],
            "SUPPORTED": [
                (
                    "The recovered formula is the intended XBL PA-to-DRAM "
                    "coordinate model because it is used by the real Quest "
                    "DDR failure recorder."
                ),
                (
                    "Section-16 base tokens are 4-KiB page numbers for the "
                    "matched qhm_shrm controller targets."
                ),
                (
                    "Section 16 is an SHRM-side register access/configuration "
                    "inventory because XBL copies it to SHRM memory and its "
                    "pages match qhm_shrm topology targets."
                ),
            ],
            "HYPOTHESIS": [
                (
                    "One or more enumerated MCCC/MC register tokens may "
                    "control final hardware address decode, interleave, or "
                    "swizzle state."
                ),
            ],
            "REFUTED": [
                (
                    "The exact bounded XBL diagnostic formula itself contains "
                    "an XOR/hash or produces two PA values for one coordinate."
                ),
                (
                    "The invert_row diagnostic string alone proves a final "
                    "physical-address row transform; its two pinned uses "
                    "report and forward a local DDR-code flag outside the "
                    "coordinate reporter."
                ),
                (
                    "Section 16's base-token/offset-token structure by itself "
                    "proves offset scaling, write opcodes, or mutable "
                    "transform semantics."
                ),
            ],
            "UNKNOWN": [
                (
                    "Whether silicon applies an additional XOR/hash/swizzle "
                    "not represented by the XBL diagnostic formula."
                ),
                (
                    "The SHRM instruction encoding and exact semantics of "
                    "section 16's two sets and offset tokens."
                ),
                (
                    "Which enumerated register, if any, controls the final "
                    "address transform and whether it remains writable after "
                    "boot."
                ),
                (
                    "Protection ordering relative to the final hardware "
                    "decode and whether a post-transform security check "
                    "exists."
                ),
                "Any normal-RAM physical-to-DRAM alias or protected-memory isolation bypass.",
            ],
        },
        "classification": "CLASS_A_OR_B_CANDIDATE_NO_ALIAS_PRIMITIVE_OBSERVED",
    }


def inventory(
    xbl_path: Path, xbl_config_path: Path, boot_log_path: Path
) -> tuple[dict[str, object], dict[str, object]]:
    paths = {
        "xbl": xbl_path,
        "xbl_config": xbl_config_path,
        "retained_boot_log": boot_log_path,
    }
    data = {label: path.read_bytes() for label, path in paths.items()}
    public_inputs: dict[str, object] = {}
    private_inputs: dict[str, object] = {}
    for label, path in paths.items():
        metadata = verify_pinned_bytes(label, data[label], PINS[label])
        public_inputs[label] = {"filename": path.name, **metadata}
        private_inputs[label] = {
            "path": str(path.resolve()),
            "filename": path.name,
            **metadata,
        }

    analysis = analyze(data["xbl"], data["xbl_config"], data["retained_boot_log"])
    common = {
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        **analysis,
    }
    private_result = {
        "schema": "sdm855-dram-coordinate-inventory-private-v1",
        "inputs": private_inputs,
        **copy.deepcopy(common),
    }
    public_result = {
        "schema": "sdm855-dram-coordinate-inventory-public-v1",
        "inputs": public_inputs,
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
        / "evidence/private/011-dram-coordinate-inventory-20260825-01.json",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=root
        / "evidence/manifests/011-dram-coordinate-inventory-20260825-01.manifest.json",
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
        args.xbl.resolve(), args.xbl_config.resolve(), args.boot_log.resolve()
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
        write_new(private_output, private_encoded, 0o600)
        write_new(manifest_output, manifest_encoded, 0o644)
    print(private_output)
    print(manifest_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
