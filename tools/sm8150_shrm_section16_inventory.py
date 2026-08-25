#!/usr/bin/env python3
"""Decode the exact SM8150 SHRM section-16 register snapshot consumer.

This is a host-only parser.  It does not execute Xtensa code and performs no
device, SMC, MMIO, partition, or firmware-write operation.  The exact XBL
embeds an Xtensa SHRM image.  Two bounded call sites in that image consume the
section-16 lists through a common helper.  This tool pins those bytes and
reconstructs the helper's address arithmetic and direction from the exact
instruction stream.
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
    from tools.sm8150_dram_coordinate_inventory import (
        SELECTED_DCB_NAME,
        extract_selected_section16,
        parse_shrm_topology,
    )
    from tools.sm8150_remapper_boundary_inventory import verify_pinned_bytes
    from tools.xbl_dcb_inventory import parse_elf64_load_segments
    from tools.xbl_memory_pipeline_inventory import (
        file_offset_to_vaddr,
        read_vaddr,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from sm8150_dram_coordinate_inventory import (
        SELECTED_DCB_NAME,
        extract_selected_section16,
        parse_shrm_topology,
    )
    from sm8150_remapper_boundary_inventory import verify_pinned_bytes
    from xbl_dcb_inventory import parse_elf64_load_segments
    from xbl_memory_pipeline_inventory import file_offset_to_vaddr, read_vaddr


XBL_PIN: Mapping[str, object] = {
    "size": 4_194_304,
    "sha256": "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37",
}
XBL_CONFIG_PIN: Mapping[str, object] = {
    "size": 4_149_248,
    "sha256": "0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c",
}

SHRM_INSTRUCTION_VA = 0x148BBE98
SHRM_INSTRUCTION_SIZE = 0x5CE0
SHRM_INSTRUCTION_SHA256 = (
    "421824b417ab28e6c0d1802c05d7ce5422e93b116973ce7f039321fb5a01a1fd"
)
SHRM_XTENSA_CODE_BASE = 0x28000
SHRM_XTENSA_CODE_DESTINATION = 0x09068000
SHRM_XTENSA_DATA_BASE = 0x22100
SHRM_XTENSA_DATA_DESTINATION = 0x09062100
SHRM_SECTION16_XTENSA_VA = 0x25100
SHRM_SECTION16_DESTINATION = 0x09065100
SHRM_SECTION16_WORKSPACE_SIZE = 0xF00

PARSER_START = 0x2D8DC
PARSER_END_EXCLUSIVE = 0x2D959
PARSER_SHA256 = "01fc5d83049d3fff7db6aa10a316dfbd07dfbd87093bb0b5a5d722aa3dfe211b"

CALLSITE_PINS: Mapping[str, Mapping[str, object]] = {
    "set0_read_callsite": {
        "start": 0x288A9,
        "end_exclusive": 0x288C7,
        "sha256": "2f247987735f8b39e6c84431b9e7ef58b549837ed61bf7898f9db1f9568caa12",
        "list_header_word": 0,
        "destination_header_word": 1,
        "capacity_expression": "header[3] - header[1]",
        "direction_argument": 0,
    },
    "set1_read_callsite": {
        "start": 0x28E15,
        "end_exclusive": 0x28E30,
        "sha256": "03720673ed08d19714f6f10ad6da2133d846b5b26fbe827bf0f2046feb9dfcc1",
        "list_header_word": 2,
        "destination_header_word": 3,
        "capacity_expression": "0xf00 - header[3]",
        "direction_argument": 0,
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError(f"u16 read outside section workspace at 0x{offset:x}")
    return struct.unpack_from("<H", data, offset)[0]


def _parse_list(
    workspace: bytes,
    *,
    list_offset: int,
    list_end: int,
    destination_offset: int,
    capacity_bytes: int,
    direction: int,
) -> dict[str, object]:
    """Decode the exact helper at Xtensa VA 0x2d8dc without touching MMIO.

    Xtensa `addx4 dst, index, base` is used in the helper as
    `base + (index << 2)`.  The other `addx4` combines an offset token with a
    page token shifted by twelve, giving `(base_page << 12) + (offset << 2)`.
    direction=0 is the observed read path; direction=1 would write the staged
    destination word back to the computed register address.
    """

    if direction not in (0, 1):
        raise ValueError("direction must be 0 (read) or 1 (write)")
    if not 0 <= list_offset < list_end <= len(workspace):
        raise ValueError("register-list bounds are invalid")
    if destination_offset < 0 or capacity_bytes < 0:
        raise ValueError("destination bounds are invalid")

    cursor = list_offset
    output_index = 0
    records: list[dict[str, object]] = []
    addresses: list[int] = []
    while True:
        if cursor + 2 > list_end:
            raise ValueError("register list has no complete terminator")
        base_count, offset_count = struct.unpack_from("<BB", workspace, cursor)
        if base_count == 0:
            terminator_offset = cursor
            break
        record_size = 2 + 2 * (base_count + offset_count)
        if cursor + record_size > list_end:
            raise ValueError("register record crosses its list boundary")
        bases = [_u16(workspace, cursor + 2 + 2 * i) for i in range(base_count)]
        offsets_start = cursor + 2 + 2 * base_count
        offsets = [_u16(workspace, offsets_start + 2 * i) for i in range(offset_count)]
        record_addresses: list[int] = []
        for base_page in bases:
            for offset_token in offsets:
                if (output_index + 1) * 4 > capacity_bytes:
                    raise ValueError("register snapshot exceeds destination capacity")
                address = (base_page << 12) + (offset_token << 2)
                record_addresses.append(address)
                addresses.append(address)
                output_index += 1
        records.append(
            {
                "section_offset": f"0x{cursor:x}",
                "base_count": base_count,
                "offset_count": offset_count,
                "base_pages": [f"0x{value:04x}" for value in bases],
                "offset_tokens": [f"0x{value:04x}" for value in offsets],
                "register_addresses": [f"0x{value:08x}" for value in record_addresses],
            }
        )
        cursor += record_size

    return {
        "list_offset": f"0x{list_offset:x}",
        "terminator_offset": f"0x{terminator_offset:x}",
        "list_end_exclusive": f"0x{list_end:x}",
        "destination_offset": f"0x{destination_offset:x}",
        "capacity_bytes": capacity_bytes,
        "capacity_words": capacity_bytes // 4,
        "direction_argument": direction,
        "direction_semantics": (
            "read MMIO word into SHRM snapshot buffer"
            if direction == 0
            else "write SHRM snapshot buffer word to MMIO"
        ),
        "record_count": len(records),
        "register_word_count": len(addresses),
        "records": records,
        "register_addresses": [f"0x{value:08x}" for value in addresses],
    }


def decode_section16_interpreter(section: bytes) -> dict[str, object]:
    """Decode both exact read callsites against a zero-extended 0xf00 workspace."""

    if len(section) < 8:
        raise ValueError("section 16 is shorter than its four-word header")
    header = struct.unpack_from("<4H", section, 0)
    list0_offset, destination0_offset, list1_offset, destination1_offset = header
    if list0_offset != 8:
        raise ValueError("unexpected list-0 offset")
    if destination0_offset != len(section):
        raise ValueError(
            "selected DCB section length is not the section-16 destination-0 offset"
        )
    if not list0_offset < list1_offset < destination0_offset < destination1_offset:
        raise ValueError("section-16 offsets are not strictly ordered")
    if destination1_offset >= SHRM_SECTION16_WORKSPACE_SIZE:
        raise ValueError("destination-1 offset exceeds SHRM workspace")

    workspace = section + bytes(SHRM_SECTION16_WORKSPACE_SIZE - len(section))
    set0 = _parse_list(
        workspace,
        list_offset=list0_offset,
        list_end=list1_offset,
        destination_offset=destination0_offset,
        capacity_bytes=destination1_offset - destination0_offset,
        direction=0,
    )
    set1 = _parse_list(
        workspace,
        list_offset=list1_offset,
        list_end=destination0_offset,
        destination_offset=destination1_offset,
        capacity_bytes=SHRM_SECTION16_WORKSPACE_SIZE - destination1_offset,
        direction=0,
    )
    return {
        "header": {
            "list0_offset": f"0x{list0_offset:x}",
            "destination0_offset": f"0x{destination0_offset:x}",
            "list1_offset": f"0x{list1_offset:x}",
            "destination1_offset": f"0x{destination1_offset:x}",
            "workspace_size": SHRM_SECTION16_WORKSPACE_SIZE,
        },
        "sets": [set0, set1],
        "address_formula": "(base_page << 12) + (offset_token << 2)",
        "offset_token_scaling_bytes": 4,
        "direction_argument_zero_is_read": True,
        "write_callsite_count": 0,
    }


def _classify_pages(
    decoded: Mapping[str, object], topology: Mapping[str, object]
) -> dict[str, object]:
    page_targets: dict[int, list[str]] = {}
    for record in topology["records"]:
        address = record["address"]
        if address is None:
            continue
        page_targets.setdefault(int(str(address), 0) >> 12, []).append(
            str(record["target"])
        )

    result_sets = []
    for register_set in decoded["sets"]:
        base_pages: dict[str, list[str]] = {}
        for record in register_set["records"]:
            for page in record["base_pages"]:
                value = int(str(page), 0)
                base_pages.setdefault(str(page), sorted(set(page_targets.get(value, []))))
        result_sets.append(
            {
                "index": len(result_sets),
                "base_page_topology_targets": base_pages,
            }
        )
    return {"sets": result_sets}


def _blob_code_pins(xbl_data: bytes) -> dict[str, object]:
    segments = parse_elf64_load_segments(xbl_data)
    blob = read_vaddr(xbl_data, segments, SHRM_INSTRUCTION_VA, SHRM_INSTRUCTION_SIZE)
    if sha256(blob) != SHRM_INSTRUCTION_SHA256:
        raise ValueError("embedded SHRM instruction blob SHA-256 mismatch")

    def blob_slice(start: int, end: int) -> bytes:
        if not SHRM_XTENSA_CODE_BASE <= start < end <= SHRM_XTENSA_CODE_BASE + len(blob):
            raise ValueError("SHRM code pin is outside the embedded blob")
        offset = start - SHRM_XTENSA_CODE_BASE
        return blob[offset : offset + (end - start)]

    parser = blob_slice(PARSER_START, PARSER_END_EXCLUSIVE)
    if sha256(parser) != PARSER_SHA256:
        raise ValueError("SHRM section-16 parser fingerprint mismatch")
    callsites = {}
    for name, pin in CALLSITE_PINS.items():
        start = int(pin["start"])
        end = int(pin["end_exclusive"])
        raw = blob_slice(start, end)
        actual = sha256(raw)
        if actual != pin["sha256"]:
            raise ValueError(f"SHRM {name} fingerprint mismatch")
        callsites[name] = {
            "start": f"0x{start:x}",
            "end_exclusive": f"0x{end:x}",
            "size": len(raw),
            "sha256": actual,
            "list_header_word": pin["list_header_word"],
            "destination_header_word": pin["destination_header_word"],
            "capacity_expression": pin["capacity_expression"],
            "direction_argument": pin["direction_argument"],
        }
    return {
        "virtual_address": f"0x{SHRM_INSTRUCTION_VA:x}",
        "size": len(blob),
        "sha256": sha256(blob),
        "xtensa_code_base": f"0x{SHRM_XTENSA_CODE_BASE:x}",
        "physical_destination": f"0x{SHRM_XTENSA_CODE_DESTINATION:x}",
        "parser_function": {
            "start": f"0x{PARSER_START:x}",
            "end_exclusive": f"0x{PARSER_END_EXCLUSIVE:x}",
            "size": PARSER_END_EXCLUSIVE - PARSER_START,
            "sha256": sha256(parser),
        },
        "direct_callsites": callsites,
        "instruction_set": "Xtensa (exact blob; binutils-compatible decode)",
    }


def analyze(xbl_data: bytes, xbl_config_data: bytes) -> dict[str, object]:
    segments = parse_elf64_load_segments(xbl_data)
    section, selected_dcb = extract_selected_section16(
        xbl_config_data, SELECTED_DCB_NAME
    )
    decoded = decode_section16_interpreter(section)
    topology = parse_shrm_topology(xbl_data)
    topology_vaddr = file_offset_to_vaddr(segments, int(topology["file_offset"], 0))
    topology["virtual_address"] = f"0x{topology_vaddr:x}"
    blob = _blob_code_pins(xbl_data)
    classified = _classify_pages(decoded, topology)

    return {
        "selected_dcb": selected_dcb,
        "shrm_instruction_blob": blob,
        "shrm_addressing": {
            "code_virtual_base": f"0x{SHRM_XTENSA_CODE_BASE:x}",
            "code_physical_destination": f"0x{SHRM_XTENSA_CODE_DESTINATION:x}",
            "data_virtual_base": f"0x{SHRM_XTENSA_DATA_BASE:x}",
            "data_physical_destination": f"0x{SHRM_XTENSA_DATA_DESTINATION:x}",
            "section16_virtual_address": f"0x{SHRM_SECTION16_XTENSA_VA:x}",
            "section16_physical_destination": f"0x{SHRM_SECTION16_DESTINATION:x}",
            "section16_virtual_to_physical_delta": f"0x{SHRM_SECTION16_DESTINATION - SHRM_XTENSA_DATA_DESTINATION - (SHRM_SECTION16_XTENSA_VA - SHRM_XTENSA_DATA_BASE):x}",
        },
        "shrm_topology": topology,
        "section16_interpreter": decoded,
        "section16_page_classification": classified,
        "claims": {
            "PROVED": [
                "The exact embedded SHRM image is an Xtensa image installed at 0x09068000.",
                "The exact SHRM helper at Xtensa VA 0x2d8dc parses base/offset records.",
                "The helper computes register addresses as (base_page << 12) + (offset_token << 2).",
                "The helper uses direction 0 to read each computed 32-bit register into a SHRM snapshot buffer.",
                "Both exact section-16 callsites pass direction 0 and stage outputs at section workspace offsets 0x230 and 0x8e8.",
                "The exact selected section-16 lists contain 430 and 64 register-word reads and fit their destination capacities.",
            ],
            "SUPPORTED": [
                "Section 16 is a boot/diagnostic controller-register snapshot inventory, not a direct transform-write command stream.",
                "The listed register families include MCCC, MC, MCCC-master, DDRSS, SHRM CSR and LLCC-visible pages matched by exact qhm_shrm topology.",
            ],
            "HYPOTHESIS": [
                "The returned snapshot words may contain final-decode or training state, but their values and lock bits are not present in the static artifacts.",
            ],
            "REFUTED": [
                "Section 16 itself is an EL1/Normal-World write primitive.",
                "The exact two section-16 consumers write the computed MCCC/MC addresses during their observed call paths.",
            ],
            "UNKNOWN": [
                "The runtime values returned by the reads and whether any listed register controls final PA-to-DRAM decode.",
                "Whether an indirect or future firmware path invokes the helper with direction 1 outside the two direct callsites in this blob.",
                "Protection ordering relative to the registers read by this diagnostic path.",
            ],
        },
        "classification": "CLASS_A_OR_B_CANDIDATE_SECTION16_READ_ONLY",
    }


def atomic_replace(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(temporary)
    write_new(temporary, data, mode)
    os.replace(temporary, path)


def inventory(xbl_path: Path, xbl_config_path: Path) -> tuple[dict[str, object], dict[str, object]]:
    xbl_data = xbl_path.read_bytes()
    config_data = xbl_config_path.read_bytes()
    inputs_public = {
        "xbl": {"filename": xbl_path.name, **verify_pinned_bytes("xbl", xbl_data, XBL_PIN)},
        "xbl_config": {
            "filename": xbl_config_path.name,
            **verify_pinned_bytes("xbl_config", config_data, XBL_CONFIG_PIN),
        },
    }
    inputs_private = {
        "xbl": {"path": str(xbl_path.resolve()), **inputs_public["xbl"]},
        "xbl_config": {"path": str(xbl_config_path.resolve()), **inputs_public["xbl_config"]},
    }
    common = {
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        **analyze(xbl_data, config_data),
    }
    return (
        {
            "schema": "sdm855-shrm-section16-inventory-private-v1",
            "inputs": inputs_private,
            **copy.deepcopy(common),
        },
        {
            "schema": "sdm855-shrm-section16-inventory-public-v1",
            "inputs": inputs_public,
            **copy.deepcopy(common),
        },
    )


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    firmware = root / "evidence/private/004-live-firmware-readonly-20260825-01"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xbl", type=Path, default=firmware / "xbl--sdb1.bin")
    parser.add_argument("--xbl-config", type=Path, default=firmware / "xbl_config--sdb2.bin")
    parser.add_argument(
        "--private-output",
        type=Path,
        default=root / "evidence/private/012-shrm-section16-inventory-20260825-01.json",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=root / "evidence/manifests/012-shrm-section16-inventory-20260825-01.manifest.json",
    )
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    private_output = args.private_output.resolve()
    manifest_output = args.manifest_output.resolve()
    if not args.replace:
        for output in (private_output, manifest_output):
            if output.exists():
                raise FileExistsError(output)
    private_result, public_result = inventory(args.xbl.resolve(), args.xbl_config.resolve())
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
