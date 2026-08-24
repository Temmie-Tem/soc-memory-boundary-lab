#!/usr/bin/env python3
"""Trace exact A90 QHEE/TZ XPU authority and BIMC_MPU initialization.

This is a host-only parser.  It performs no device, SMC, or MMIO access and
emits no firmware bytes.  Exact A90 XBL, TrustZone, QHEE/hyp, and devcfg inputs
are pinned by size and SHA-256.  Comparative SDM660 sources supply names and
field documentation only; every SM8150 address and value is verified against
the pinned A90 binaries.
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
    from tools.sm8150_xpu_policy_inventory import (
        POLICY_TABLES,
        decode_mpu_region_permissions,
        parse_dal_u32_property,
        parse_mpu_regions,
        parse_policy_descriptors,
        parse_xpu_registry,
        region_contains,
    )
    from tools.xbl_dcb_inventory import LoadSegment, parse_elf64_load_segments
    from tools.xbl_memory_pipeline_inventory import (
        file_offset_to_vaddr,
        read_vaddr,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from sm8150_xpu_policy_inventory import (
        POLICY_TABLES,
        decode_mpu_region_permissions,
        parse_dal_u32_property,
        parse_mpu_regions,
        parse_policy_descriptors,
        parse_xpu_registry,
        region_contains,
    )
    from xbl_dcb_inventory import LoadSegment, parse_elf64_load_segments
    from xbl_memory_pipeline_inventory import file_offset_to_vaddr, read_vaddr


PINS: Mapping[str, Mapping[str, object]] = {
    "xbl": {
        "size": 4_194_304,
        "sha256": "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37",
    },
    "trustzone": {
        "size": 4_194_304,
        "sha256": "a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab",
    },
    "hyp": {
        "size": 1_048_576,
        "sha256": "646f8fca08b0eff56b1d8415d81c3041a775c1871400dc57448cb5103405a8e1",
    },
    "devcfg": {
        "size": 131_072,
        "sha256": "0399578253dd293dfc961c6a1077f660834df3ae5e1d65555f4225e327a03d14",
    },
}

SMC_HYP_ASSIGN = 0x02000C16
SMC_ENABLE_TOGGLE_XPU = 0x02000C23
SMC_MPU_LOCK_HLOS_REGION = 0x02000C24
SMC_RPM_ONLINE_DUMP = 0x0200030F
SMC_SECURITY_ALLOWS_DUMP = 0x02000310
SMC_QSEE_APP_REGION_NOTIFICATION = 0x32000105

SYSCALL_RECORD_SIZE = 24
TZ_SYSCALL_RECORDS: Mapping[str, Mapping[str, int]] = {
    "enable_toggle_xpu": {
        "record_vaddr": 0x1C12A7C8,
        "reserved": 0,
        "smc_id": SMC_ENABLE_TOGGLE_XPU,
        "param_id": 0x2,
        "flags": 0,
        "handler": 0x1C0A9A44,
    },
    "rpm_online_dump": {
        "record_vaddr": 0x1C12A990,
        "reserved": 0,
        "smc_id": SMC_RPM_ONLINE_DUMP,
        "param_id": 0x1,
        "flags": 0,
        "handler": 0x1C050B9C,
    },
    "hyp_assign_fallback": {
        "record_vaddr": 0x1C12AAF8,
        "reserved": 0,
        "smc_id": SMC_HYP_ASSIGN,
        "param_id": 0x1117,
        "flags": 0x1,
        "handler": 0x1C0A6DE4,
    },
    "qsee_app_region_notification": {
        "record_vaddr": 0x1C12ACA8,
        "reserved": 0,
        "smc_id": SMC_QSEE_APP_REGION_NOTIFICATION,
        "param_id": 0x22,
        "flags": 0x13,
        "handler": 0x1C0C30F8,
    },
    "security_allows_dump": {
        "record_vaddr": 0x1C12B140,
        "reserved": 0,
        "smc_id": SMC_SECURITY_ALLOWS_DUMP,
        "param_id": 0,
        "flags": 0x1,
        "handler": 0x1C054734,
    },
}

HYP_SYSCALL_RECORDS: Mapping[str, Mapping[str, int]] = {
    "qsee_app_region_notification": {
        "file_offset": 0x61D58,
        "record_vaddr": 0x8575FB18,
        "reserved": 0,
        "smc_id": SMC_QSEE_APP_REGION_NOTIFICATION,
        "param_id": 0x22,
        "flags": 0,
        "handler": 0x85716348,
    },
    "rpm_online_dump": {
        "file_offset": 0x61D70,
        "record_vaddr": 0x8575FB30,
        "reserved": 0,
        "smc_id": SMC_RPM_ONLINE_DUMP,
        "param_id": 0x1,
        "flags": 0,
        "handler": 0x857161C0,
    },
    "hyp_assign": {
        "file_offset": 0x61EC0,
        "record_vaddr": 0x8575FC80,
        "reserved": 0,
        "smc_id": SMC_HYP_ASSIGN,
        "param_id": 0x1117,
        "flags": 0x80000000,
        "handler": 0x85723B90,
    },
}

TZ_FUNCTION_FINGERPRINTS: Mapping[str, tuple[int, int, str]] = {
    "xpu_toggle_handler": (
        0x1C0A9A44,
        0x1C0A9B28,
        "687992fb5fe4a057e3d2205c0df1faf7fa857fed8e65fe1575e0af7359190f24",
    ),
    "xpu_base_to_id": (
        0x1C0A9B28,
        0x1C0A9BC8,
        "0f62978f7ef8395501440eb3b4211f68c9612440309a965ceb7f656722c9d681",
    ),
    "mpu_lock_area": (
        0x1C0A9D5C,
        0x1C0A9E14,
        "a5e001a759c4497ea0500f22f660cdccac16d1a48319684678caa081e37b23e0",
    ),
    "bimc_topology_fanout": (
        0x1C0A9E14,
        0x1C0A9F44,
        "8fdcac4e42a4517c8b9e9e726880c60d9d61f5a0f74683f6aaec73f3abfd5ddc",
    ),
    "mpu_reconfigure": (
        0x1C0A9F44,
        0x1C0AA0B4,
        "1836348473626257ad0df6f4bbc71cef9552e20405b13971bd0e8a239dc30110",
    ),
    "mpu_unlock_area": (
        0x1C0AA0B4,
        0x1C0AA168,
        "b59319058d1da89e569db420d816eb43b6c768d5de61dba1dec7837eb4bb8ffa",
    ),
    "mpu_lock_memory": (
        0x1C0AB624,
        0x1C0AB6C8,
        "f0f120559d8439034be03c69357fb2e1db386d2e082d67463b252f6301ac837a",
    ),
    "mpu_lock_memory_internal": (
        0x1C0AB6C8,
        0x1C0AB718,
        "06ac4f40e157bd5f5e13c68ba179e396b24c0ea51fd795205f2607cc67a87583",
    ),
    "master_mpu_boot_calls": (
        0x1C0A40F8,
        0x1C0A4148,
        "44be68f41d513f066e020b45e8e271d860100af1f441c1ad66d435cdd27eafea",
    ),
    "master_mpu_init": (
        0x1C0ACE70,
        0x1C0AD0FC,
        "82d76ae020a83bfc857d1e7d6d4fde29ab9cd596e93e2a47187e857208fe684d",
    ),
    "allowed_disable_getter": (
        0x1C0A2630,
        0x1C0A264C,
        "f3d5e26eefd2ca779c1bbc14023fa5fc1660c34fa109f4e1cb07c40759aa329c",
    ),
    "hyp_assign_fallback_handler": (
        0x1C0A6DE4,
        0x1C0A76FC,
        "9670da741791d1a8309a0111411b8adf8a122681165c7714c7148764ccb509b7",
    ),
    "tz_assignment_core": (
        0x1C0A5564,
        0x1C0A61CC,
        "f665a344e099eac64b352747229a910f6aec56cee8aefbd0d8036098b3c982b1",
    ),
    "qsee_app_region_handler": (
        0x1C0C30F8,
        0x1C0C3138,
        "241abf288059ea0e3c64fb5e99def7a1c6522607fae27f7967d94b50d558639c",
    ),
    "rpm_online_dump_noop": (
        0x1C050B9C,
        0x1C050BA0,
        "110f46b5b35c069160560c6ad6786f647dd44e8760a52a46fc22dbbcd7630b91",
    ),
    "hal_init_wrapper": (
        0x1C0FA7D4,
        0x1C0FA8B0,
        "c1c1747024c172ec146db65d47b8310cd37aea6f2c543e0055381382d18bcd78",
    ),
    "xpu3_init": (
        0x1C0FB88C,
        0x1C0FB980,
        "001a616ce5ef1dd92a35427f8b310dc92370efd8baaffde924b6e484e33290f4",
    ),
    "xpu3_restore": (
        0x1C0FBBD8,
        0x1C0FBC50,
        "6e7a1b6c25cfa45eeefddf24ef81841395538e7ef8c438931214cce04300c0de",
    ),
    "xpu3_reset": (
        0x1C0FBC50,
        0x1C0FBCB8,
        "2b62550545b91f66ff046b3f0f33e04d296eff9343ffa240bbe7ba91edd86762",
    ),
    "static_config_head": (
        0x1C0A95E4,
        0x1C0A9640,
        "98df542b9ed8a457e1856f918065aedf54cf7c66ff76e2960ece239642dfa908",
    ),
}

HYP_FUNCTION_FINGERPRINTS: Mapping[str, tuple[int, int, str]] = {
    "rpm_region_share_handler": (
        0x857161C0,
        0x85716348,
        "8af323a1c2ec9cd0a21954691157b374c39201dffcf2a71cc9a46f2cc7f6075c",
    ),
    "app_region_intercept": (
        0x85716348,
        0x857165BC,
        "46930a5f2b8b0beaf2fb1d8b812cc7ff30216567be53b7d10c748c8f14e4133a",
    ),
    "hyp_assign": (
        0x85723B90,
        0x85724084,
        "2e5cb0c9f9204d29cc62b27d61cd24c348cb4951f380d94ed65f01647be5a5b6",
    ),
    "ac_map_memory_range_wrapper": (
        0x8573581C,
        0x857358A8,
        "7f5eee7d9bb6bc0376eee8399ae8ef39b481a3b35a53ab93ec4479b0002692af",
    ),
}

TZ_PINNED_INSTRUCTIONS: Mapping[int, int] = {
    # TZ fallback assignment -> assignment core -> high-level MPU lock.
    0x1C0A7594: 0x97FFF7F4,
    0x1C0A60F4: 0x9400154C,
    0x1C0AB6A4: 0x94000009,
    0x1C0AB704: 0x17FFF996,
    # SM8150 topology fanout emits BIMC_MPU0..3 resource IDs.
    0x1C0A9E60: 0x528005C0,
    0x1C0A9E8C: 0x528005E0,
    0x1C0A9E98: 0x320017E0,
    0x1C0A9EA4: 0x321A03E0,
    # Toggle handler calls whitelist getter on its disable path.
    0x1C0A9ABC: 0x97FFE2DD,
    # Static configuration begins with w23 = 0x0001c800.
    0x1C0A960C: 0x52990017,
    0x1C0A9610: 0x72A00037,
    # HAL restore/reset preserve control-register mask 0x2.
    0x1C0FBBE4: 0x121F0129,
    0x1C0FBBE8: 0x32000129,
    0x1C0FBC74: 0x121F0129,
}

HYP_PINNED_INSTRUCTIONS: Mapping[int, int] = {
    # RPM path invokes the generic TZ SMC wrapper twice.
    0x85716200: 0x940007C0,
    0x85716230: 0x940007B4,
    # App-region intercept constructs SMC 0x32000105 and invokes TZ.
    0x8571653C: 0x528020A0,
    0x85716540: 0x72A64000,
    0x8571655C: 0x940006E9,
    # QHEE hyp_assign calls its local AC mapping wrapper.
    0x8572403C: 0x940045F8,
}

TOPOLOGY_JUMP_TABLE_VADDR = 0x1C122B40
TOPOLOGY_JUMP_TARGETS = (
    0x1C0A9F28,
    0x1C0A9E40,
    0x1C0A9E6C,
    0x1C0A9E54,
    0x1C0A9E74,
    0x1C0A9EAC,
)
TOPOLOGY_KNOWN_RESOURCE_IDS = (0x2E, 0x2F, 0x3F, 0x40, 0x3A)
TOPOLOGY_UNRESOLVED_RESOURCE_IDS = (0x51, 0x52, 0x53, 0x54)
ALLOWED_DISABLE_COUNT_VADDR = 0x1C122A90

MASTER_MPU_POINTER_TABLE_VADDR = 0x1C155880
MASTER_MPU_SELECTORS: Mapping[int, tuple[int, int, str]] = {
    0x1D: (0x1C155700, 0x39, "CNOC_AOSS_MPU"),
    0x1E: (0x1C155400, 0x1D, "ANOC2_MPU"),
    0x23: (0x1C155580, 0x31, "MSS_NAV_MPU"),
}

CONTROLLER_INSTANCES = (
    {"instance": 0, "remapper": 0x09248080, "bimc_mpu": 0x0924E000, "resource_id": 0x2E},
    {"instance": 1, "remapper": 0x092C8080, "bimc_mpu": 0x092CE000, "resource_id": 0x2F},
    {"instance": 2, "remapper": 0x09348080, "bimc_mpu": 0x0934E000, "resource_id": 0x3F},
    {"instance": 3, "remapper": 0x093C8080, "bimc_mpu": 0x093CE000, "resource_id": 0x40},
)

BROAD_POLICY_EXPECTED: Mapping[str, Mapping[str, int]] = {
    "MEMNOC_MS_MPU": {
        "index": 0,
        "flags": 0x9,
        "read_vmid": 0x80000000,
        "write_vmid": 0x80000000,
        "start": 0,
        "end_exclusive": 0x10000000,
    },
    "CNOC_SNOC_MS_MPU": {
        "index": 5,
        "flags": 0x9,
        "read_vmid": 0xF0000000,
        "write_vmid": 0xF0000000,
        "start": 0x09000000,
        "end_exclusive": 0x09800000,
    },
}

XBL_DIAGNOSTIC_TABLE_RECORDS: Mapping[int, int] = {
    0x2E: 0x2D9660,
    0x2F: 0x2D9670,
    0x3F: 0x2D96F0,
    0x40: 0x2D9730,
}
XBL_MARKERS: Mapping[str, tuple[bytes, int]] = {
    "xpu_version": (b"XPU_VER_20190409225523", 0x2D78A0),
    "embedded_tz_image_version": (
        b"QC_IMAGE_VERSION_STRING=TZ.XF.5.2-00181",
        0x2D9300,
    ),
    "xpu_violation_reporter": (b"print_xpu_info", 0x330BD0),
}

COMPARATIVE_SOURCE = {
    "status": "COMPARATIVE_NOT_EXACT_SM8150_SOURCE",
    "repository": "David112x/android-firmware-qti-sdm660",
    "commit": "b5e5bb9ed6c92442fd502b3e726d7c8024dc0763",
    "files": [
        {
            "path": "trustzone_images/core/securemsm/accesscontrol/api/AccessControlHyp.h",
            "sha256": "4e39a89cd27d2aef446eb76e04061c0af3bd80c2430b36bbf07f888cafdc66c9",
            "relevance": "Documents ACMapMemoryRange as a hypervisor page-table mapping API.",
        },
        {
            "path": "trustzone_images/core/securemsm/accesscontrol/api/AccessControlTz.h",
            "sha256": "b31edbf4afd41d8d5d4faa0b62ab01f74b7fd149286ee0486b7bbe45bca6f724",
            "relevance": "Documents TZ MPU lock APIs and access-control record layouts.",
        },
        {
            "path": "trustzone_images/core/securemsm/trustzone/qsee/include/tz_syscall_pub.h",
            "sha256": "4ec06500c274e64fc09ccbfb93e5de34a2d06b7971df05fda5787de061b8512f",
            "relevance": "Names SMC 0x02000c23 and 0x02000c24 and their parameters.",
        },
        {
            "path": "trustzone_images/core/kernel/xpu3/hal/inc/HALxpu3.h",
            "sha256": "07291481f1b28c201ad3043692a53188ccc8dae476c207bea06eafd6c620b414",
            "relevance": "Documents XPU3 control and secure-config-write-disable fields.",
        },
        {
            "path": "trustzone_images/core/securemsm/accesscontrol/build/qsee/A53_64/KAJAANAA/src/components/xpu/v3/ACXpu.o",
            "sha256": "376ddb769505a29895b88f2af079e9ddf8c154faf087d0dcd2f851a840cd4fe0",
            "relevance": "Unstripped comparative object supplies matching TZ XPU function names.",
        },
    ],
    "claim_boundary": (
        "Comparative material supplies names and field documentation only; "
        "all SM8150 addresses, instruction words, tables, and SMC records are "
        "independently pinned to exact A90 firmware bytes."
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_pinned_bytes(
    label: str, data: bytes, pin: Mapping[str, object]
) -> dict[str, object]:
    expected_size = int(pin["size"])
    expected_sha256 = str(pin["sha256"])
    digest = sha256(data)
    if len(data) != expected_size:
        raise ValueError(f"{label} size mismatch: {len(data)} != {expected_size}")
    if digest != expected_sha256:
        raise ValueError(
            f"{label} SHA-256 mismatch: {digest} != {expected_sha256}"
        )
    return {"size": len(data), "sha256": digest, "pin_verified": True}


def all_offsets(data: bytes, needle: bytes) -> list[int]:
    if not needle:
        raise ValueError("needle must not be empty")
    result: list[int] = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return result
        result.append(offset)
        cursor = offset + 1


def parse_syscall_record(
    data: bytes, segments: Sequence[LoadSegment], vaddr: int
) -> dict[str, int | str]:
    raw = read_vaddr(data, segments, vaddr, SYSCALL_RECORD_SIZE)
    reserved, smc_id, param_id, flags, handler = struct.unpack("<IIIIQ", raw)
    return {
        "record_vaddr": vaddr,
        "reserved": reserved,
        "smc_id": smc_id,
        "param_id": param_id,
        "flags": flags,
        "handler": handler,
        "raw_sha256": sha256(raw),
    }


def verify_syscall_records(
    label: str,
    data: bytes,
    segments: Sequence[LoadSegment],
    specifications: Mapping[str, Mapping[str, int]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    fields = ("reserved", "smc_id", "param_id", "flags", "handler")
    for name, expected in specifications.items():
        vaddr = int(expected["record_vaddr"])
        if "file_offset" in expected:
            file_offset = int(expected["file_offset"])
            derived = file_offset_to_vaddr(segments, file_offset, SYSCALL_RECORD_SIZE)
            if derived != vaddr:
                raise ValueError(
                    f"{label} {name} record VA 0x{derived:x} != 0x{vaddr:x}"
                )
        record = parse_syscall_record(data, segments, vaddr)
        for field in fields:
            if int(record[field]) != int(expected[field]):
                raise ValueError(
                    f"{label} {name} {field}=0x{int(record[field]):x} "
                    f"!= 0x{int(expected[field]):x}"
                )
        output[name] = {
            "record_vaddr": f"0x{vaddr:x}",
            **(
                {"file_offset": f"0x{int(expected['file_offset']):x}"}
                if "file_offset" in expected
                else {}
            ),
            "reserved": record["reserved"],
            "smc_id": f"0x{int(record['smc_id']):08x}",
            "param_id": f"0x{int(record['param_id']):x}",
            "flags": f"0x{int(record['flags']):08x}",
            "handler": f"0x{int(record['handler']):x}",
            "raw_sha256": record["raw_sha256"],
        }
    return output


def verify_functions(
    data: bytes,
    segments: Sequence[LoadSegment],
    specifications: Mapping[str, tuple[int, int, str]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for name, (start, end, expected_hash) in specifications.items():
        raw = read_vaddr(data, segments, start, end - start)
        digest = sha256(raw)
        if digest != expected_hash:
            raise ValueError(
                f"{name} hash mismatch: {digest} != pinned {expected_hash}"
            )
        output[name] = {
            "start": f"0x{start:x}",
            "end_exclusive": f"0x{end:x}",
            "size": end - start,
            "sha256": digest,
        }
    return output


def verify_instructions(
    label: str,
    data: bytes,
    segments: Sequence[LoadSegment],
    expected: Mapping[int, int],
) -> list[dict[str, str]]:
    output = []
    for address, expected_word in expected.items():
        word = struct.unpack("<I", read_vaddr(data, segments, address, 4))[0]
        if word != expected_word:
            raise ValueError(
                f"{label} instruction 0x{address:x}=0x{word:08x} "
                f"!= 0x{expected_word:08x}"
            )
        output.append({"address": f"0x{address:x}", "word": f"0x{word:08x}"})
    return output


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def aarch64_direct_branch_targets(
    raw: bytes, start_vaddr: int
) -> dict[str, list[int]]:
    if len(raw) % 4:
        raise ValueError("AArch64 code length must be a multiple of four")
    calls: list[int] = []
    jumps: list[int] = []
    for offset in range(0, len(raw), 4):
        word = struct.unpack_from("<I", raw, offset)[0]
        opcode = word & 0xFC000000
        if opcode not in (0x94000000, 0x14000000):
            continue
        target = start_vaddr + offset + (_sign_extend(word & 0x03FFFFFF, 26) << 2)
        (calls if opcode == 0x94000000 else jumps).append(target)
    return {"calls": calls, "jumps": jumps}


def _function_branches(
    data: bytes,
    segments: Sequence[LoadSegment],
    specification: tuple[int, int, str],
) -> dict[str, list[int]]:
    start, end, _ = specification
    return aarch64_direct_branch_targets(
        read_vaddr(data, segments, start, end - start), start
    )


def parse_master_mpu_selectors(
    data: bytes,
    segments: Sequence[LoadSegment],
    registry_by_id: Mapping[int, Mapping[str, object]],
) -> list[dict[str, object]]:
    output = []
    for selector, (expected_pointer, expected_resource, expected_name) in (
        MASTER_MPU_SELECTORS.items()
    ):
        pointer = struct.unpack(
            "<Q",
            read_vaddr(
                data,
                segments,
                MASTER_MPU_POINTER_TABLE_VADDR + selector * 8,
                8,
            ),
        )[0]
        if pointer != expected_pointer:
            raise ValueError(
                f"master selector 0x{selector:x} pointer 0x{pointer:x} "
                f"!= 0x{expected_pointer:x}"
            )
        embedded_selector = struct.unpack("<I", read_vaddr(data, segments, pointer, 4))[0]
        resource_id = struct.unpack(
            "<I", read_vaddr(data, segments, pointer + 312, 4)
        )[0]
        registry = registry_by_id.get(resource_id)
        if (
            embedded_selector != selector
            or resource_id != expected_resource
            or registry is None
            or registry["name"] != expected_name
        ):
            raise ValueError(f"master selector 0x{selector:x} binding mismatch")
        output.append(
            {
                "selector": f"0x{selector:x}",
                "record_vaddr": f"0x{pointer:x}",
                "resource_id": f"0x{resource_id:x}",
                "resource_name": expected_name,
            }
        )
    return output


def _format_policy_hit(
    resource_name: str, resource_id: int, region: Mapping[str, int]
) -> dict[str, object]:
    permissions = decode_mpu_region_permissions(region)
    return {
        "resource": resource_name,
        "resource_id": f"0x{resource_id:x}",
        "region_index": region["index"],
        "flags": f"0x{region['flags']:x}",
        "read_vmid": f"0x{region['read_vmid']:08x}",
        "write_vmid": f"0x{region['write_vmid']:08x}",
        "start": f"0x{region['start']:08x}",
        "end_exclusive": f"0x{region['end_exclusive']:08x}",
        "owner": permissions["owner"],
        "hlos_read": permissions["hlos_present_in_read_mask"],
        "hlos_write": permissions["hlos_present_in_write_mask"],
    }


def inventory_controller_aperture_policy(
    data: bytes,
    segments: Sequence[LoadSegment],
    registry: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    registry_by_id = {int(record["resource_id"]): record for record in registry}
    branches: dict[str, object] = {}
    all_addresses = [
        int(instance[field])
        for instance in CONTROLLER_INSTANCES
        for field in ("remapper", "bimc_mpu")
    ]
    for label, specification in POLICY_TABLES.items():
        descriptors = parse_policy_descriptors(
            data,
            segments,
            int(specification["table_vaddr"]),
            int(specification["expected_count"]),
        )
        parsed = []
        for descriptor in descriptors:
            resource_id = int(descriptor["resource_id"])
            registry_record = registry_by_id.get(resource_id)
            if registry_record is None:
                raise ValueError(f"policy resource 0x{resource_id:x} absent from registry")
            regions = parse_mpu_regions(
                data,
                segments,
                int(descriptor["region_vaddr"]),
                int(descriptor["region_count"]),
            )
            parsed.append((str(registry_record["name"]), resource_id, regions))

        address_results = []
        for address in all_addresses:
            hits = [
                (name, resource_id, region)
                for name, resource_id, regions in parsed
                for region in regions
                if region_contains(region, address)
            ]
            by_name = {name: region for name, _, region in hits}
            for expected_name, expected_fields in BROAD_POLICY_EXPECTED.items():
                region = by_name.get(expected_name)
                if region is None:
                    raise ValueError(
                        f"{label} 0x{address:x} lacks {expected_name} coverage"
                    )
                for field, expected in expected_fields.items():
                    if int(region[field]) != expected:
                        raise ValueError(
                            f"{label} {expected_name} {field} mismatch at 0x{address:x}"
                        )
                permissions = decode_mpu_region_permissions(region)
                if permissions["hlos_present_in_read_mask"] or permissions[
                    "hlos_present_in_write_mask"
                ]:
                    raise ValueError(f"{label} {expected_name} unexpectedly grants HLOS")
            address_results.append(
                {
                    "address": f"0x{address:08x}",
                    "hits": [
                        _format_policy_hit(name, resource_id, region)
                        for name, resource_id, region in hits
                    ],
                }
            )
        branches[label] = {
            "selector_predicate": specification["selector_predicate"],
            "addresses": address_results,
        }

    return {
        "instances": [
            {
                "instance": instance["instance"],
                "remapper": f"0x{int(instance['remapper']):08x}",
                "bimc_mpu": f"0x{int(instance['bimc_mpu']):08x}",
                "bimc_resource_id": f"0x{int(instance['resource_id']):x}",
            }
            for instance in CONTROLLER_INSTANCES
        ],
        "selector_branches": branches,
        "branch_invariant_broad_coverage": True,
        "broad_protectors": list(BROAD_POLICY_EXPECTED),
        "static_hlos_grant": False,
        "runtime_register_readback": "UNKNOWN",
    }


def inventory_xbl_diagnostic_boundary(xbl: bytes) -> dict[str, object]:
    markers = {}
    for name, (needle, expected_offset) in XBL_MARKERS.items():
        offsets = all_offsets(xbl, needle)
        if expected_offset not in offsets:
            raise ValueError(f"XBL marker {name} missing at 0x{expected_offset:x}")
        markers[name] = {
            "expected_file_offset": f"0x{expected_offset:x}",
            "occurrence_count": len(offsets),
            "all_file_offsets": [f"0x{offset:x}" for offset in offsets],
        }

    table_records = []
    bases_by_id = {
        int(instance["resource_id"]): int(instance["bimc_mpu"])
        for instance in CONTROLLER_INSTANCES
    }
    for resource_id, expected_offset in XBL_DIAGNOSTIC_TABLE_RECORDS.items():
        raw = xbl[expected_offset : expected_offset + 16]
        if len(raw) != 16:
            raise ValueError("truncated XBL diagnostic record")
        parsed_id, base = struct.unpack("<QQ", raw)
        if parsed_id != resource_id or base != bases_by_id[resource_id]:
            raise ValueError(f"XBL diagnostic record 0x{resource_id:x} mismatch")
        table_records.append(
            {
                "file_offset": f"0x{expected_offset:x}",
                "resource_id": f"0x{resource_id:x}",
                "base": f"0x{base:08x}",
                "raw_sha256": sha256(raw),
            }
        )
    return {
        "markers": markers,
        "bimc_records": table_records,
        "interpretation": (
            "The BIMC base literals are records in a TZ-branded XPU diagnostic "
            "region. Their presence is not evidence that the main XBL program "
            "writes BIMC policy registers."
        ),
        "main_xbl_bimc_policy_writer": "NOT_PROVED",
    }


def analyze(
    xbl: bytes, tz: bytes, hyp: bytes, devcfg: bytes
) -> dict[str, object]:
    tz_segments = parse_elf64_load_segments(tz)
    hyp_segments = parse_elf64_load_segments(hyp)
    devcfg_segments = parse_elf64_load_segments(devcfg)

    registry = parse_xpu_registry(tz, tz_segments)
    registry_by_id = {int(record["resource_id"]): record for record in registry}
    registry_by_name = {str(record["name"]): record for record in registry}
    for instance in CONTROLLER_INSTANCES:
        resource_id = int(instance["resource_id"])
        expected_name = f"BIMC_MPU{instance['instance']}"
        record = registry_by_id.get(resource_id)
        if (
            record is None
            or record["name"] != expected_name
            or int(record["base"]) != int(instance["bimc_mpu"])
        ):
            raise ValueError(f"exact TZ registry mismatch for {expected_name}")

    tz_syscalls = verify_syscall_records(
        "TZ", tz, tz_segments, TZ_SYSCALL_RECORDS
    )
    hyp_syscalls = verify_syscall_records(
        "HYP", hyp, hyp_segments, HYP_SYSCALL_RECORDS
    )
    tz_functions = verify_functions(tz, tz_segments, TZ_FUNCTION_FINGERPRINTS)
    hyp_functions = verify_functions(hyp, hyp_segments, HYP_FUNCTION_FINGERPRINTS)
    tz_instructions = verify_instructions(
        "TZ", tz, tz_segments, TZ_PINNED_INSTRUCTIONS
    )
    hyp_instructions = verify_instructions(
        "HYP", hyp, hyp_segments, HYP_PINNED_INSTRUCTIONS
    )

    whitelist_count = struct.unpack(
        "<Q", read_vaddr(tz, tz_segments, ALLOWED_DISABLE_COUNT_VADDR, 8)
    )[0]
    if whitelist_count != 0:
        raise ValueError(f"XPU disable whitelist count is {whitelist_count}, not zero")

    topology_targets = tuple(
        struct.unpack(
            "<Q", read_vaddr(tz, tz_segments, TOPOLOGY_JUMP_TABLE_VADDR + i * 8, 8)
        )[0]
        for i in range(len(TOPOLOGY_JUMP_TARGETS))
    )
    if topology_targets != TOPOLOGY_JUMP_TARGETS:
        raise ValueError("SM8150 BIMC topology jump table mismatch")
    for resource_id in TOPOLOGY_UNRESOLVED_RESOURCE_IDS:
        if resource_id in registry_by_id:
            raise ValueError(f"unresolved topology ID 0x{resource_id:x} became registered")

    toggle_branches = _function_branches(
        tz, tz_segments, TZ_FUNCTION_FINGERPRINTS["xpu_toggle_handler"]
    )
    for target in (0x1C0A9B28, 0x1C0FA8B0, 0x1C054590, 0x1C0A2630):
        if target not in toggle_branches["calls"]:
            raise ValueError(f"toggle handler lacks expected call 0x{target:x}")

    tz_assign_dispatch = _function_branches(
        tz, tz_segments, TZ_FUNCTION_FINGERPRINTS["hyp_assign_fallback_handler"]
    )
    tz_assign_core = _function_branches(
        tz, tz_segments, TZ_FUNCTION_FINGERPRINTS["tz_assignment_core"]
    )
    tz_lock_internal = _function_branches(
        tz, tz_segments, TZ_FUNCTION_FINGERPRINTS["mpu_lock_memory_internal"]
    )
    if 0x1C0A5564 not in tz_assign_dispatch["calls"]:
        raise ValueError("TZ assignment handler no longer calls assignment core")
    if 0x1C0AB624 not in tz_assign_core["calls"]:
        raise ValueError("TZ assignment core no longer calls MPU lock")
    if 0x1C0A9D5C not in tz_lock_internal["jumps"]:
        raise ValueError("TZ lock path no longer tail-calls MPU lock area")

    hyp_assign_branches = _function_branches(
        hyp, hyp_segments, HYP_FUNCTION_FINGERPRINTS["hyp_assign"]
    )
    if 0x8573581C not in hyp_assign_branches["calls"]:
        raise ValueError("QHEE hyp_assign lacks local AC mapping call")
    if 0x85718100 in hyp_assign_branches["calls"]:
        raise ValueError("QHEE hyp_assign unexpectedly re-enters TZ directly")

    hyp_app_branches = _function_branches(
        hyp, hyp_segments, HYP_FUNCTION_FINGERPRINTS["app_region_intercept"]
    )
    if 0x85718100 not in hyp_app_branches["calls"]:
        raise ValueError("QHEE app-region intercept lacks TZ SMC call")
    tz_app_branches = _function_branches(
        tz, tz_segments, TZ_FUNCTION_FINGERPRINTS["qsee_app_region_handler"]
    )
    if not {0x1C0C54E8, 0x1C03AA8C}.issubset(tz_app_branches["calls"]):
        raise ValueError("TZ app-region handler call graph mismatch")

    if read_vaddr(tz, tz_segments, 0x1C050B9C, 4) != struct.pack("<I", 0xD65F03C0):
        raise ValueError("TZ RPM online-dump handler is no longer a one-ret no-op")

    toggle_hyp_literals = all_offsets(hyp, struct.pack("<I", SMC_ENABLE_TOGGLE_XPU))
    hlos_lock_tz_literals = all_offsets(
        tz, struct.pack("<I", SMC_MPU_LOCK_HLOS_REGION)
    )
    if toggle_hyp_literals or hlos_lock_tz_literals:
        raise ValueError("previously absent XPU SMC literal is now present")

    devcfg_xpu = parse_dal_u32_property(devcfg, devcfg_segments)
    if devcfg_xpu["value"] != 0:
        raise ValueError("exact devcfg requests XPU access-control disable")

    master_selectors = parse_master_mpu_selectors(
        tz, tz_segments, registry_by_id
    )
    controller_policy = inventory_controller_aperture_policy(
        tz, tz_segments, registry
    )
    xbl_boundary = inventory_xbl_diagnostic_boundary(xbl)

    known_topology_resources = []
    for resource_id in TOPOLOGY_KNOWN_RESOURCE_IDS:
        record = registry_by_id[resource_id]
        known_topology_resources.append(
            {
                "resource_id": f"0x{resource_id:x}",
                "name": record["name"],
                "base": f"0x{int(record['base']):08x}",
            }
        )

    return {
        "exact_syscall_records": {
            "record_layout": "<u32 reserved, u32 smc_id, u32 param_id, u32 flags, u64 handler>",
            "record_size": SYSCALL_RECORD_SIZE,
            "trustzone": tz_syscalls,
            "qhee_hyp": hyp_syscalls,
        },
        "qhee_assignment_boundary": {
            "hyp_assign_handler": "0x85723b90",
            "local_ac_map_memory_range_wrapper": "0x8573581c",
            "direct_calls_local_wrapper": True,
            "direct_calls_generic_tz_smc_wrapper": False,
            "interpretation": (
                "The exact QHEE intercept enforces ownership and maps through "
                "its local stage-2/SMMU access-control path; this handler is not "
                "a direct BIMC XPU writer."
            ),
        },
        "trustzone_assignment_boundary": {
            "same_smc_id_fallback_registered": True,
            "handler": "0x1c0a6de4",
            "assignment_core": "0x1c0a5564",
            "mpu_lock_memory": "0x1c0ab624",
            "mpu_lock_area": "0x1c0a9d5c",
            "dynamic_bimc_reconfigure_reached": True,
            "interpretation": (
                "The exact TZ fallback is a separate enforcement implementation "
                "whose memory-lock path reaches dynamic BIMC/LLCC MPU policy."
            ),
        },
        "named_qhee_tz_services": {
            "rpm_region_share": {
                "qhee_handler": "0x857161c0",
                "tz_smc_ids": ["0x02000310", "0x0200030f"],
                "exact_tz_rpm_handler": "0x1c050b9c",
                "exact_tz_handler_is_single_ret_noop": True,
                "generic_xpu_mutation_primitive": False,
            },
            "qsee_app_region_notification": {
                "qhee_handler": "0x85716348",
                "tz_smc_id": "0x32000105",
                "tz_handler": "0x1c0c30f8",
                "tz_direct_call_targets": ["0x1c0c54e8", "0x1c03aa8c"],
                "direct_bimc_xpu_call": False,
            },
        },
        "xpu_toggle_boundary": {
            "smc_id": "0x02000c23",
            "registered_in_tz": True,
            "literal_present_in_hyp": False,
            "disable_whitelist_count_vaddr": f"0x{ALLOWED_DISABLE_COUNT_VADDR:x}",
            "disable_whitelist_count": whitelist_count,
            "disable_path_accepts_any_base": False,
            "enable_path": "registered-base lookup followed by HAL restore",
            "arbitrary_mmio_writer": False,
            "tz_mpu_lock_hlos_region_smc_literal_present": False,
        },
        "dynamic_bimc_policy": {
            "topology_jump_table_vaddr": f"0x{TOPOLOGY_JUMP_TABLE_VADDR:x}",
            "topology_jump_targets": [f"0x{target:x}" for target in topology_targets],
            "known_fanout_resources": known_topology_resources,
            "unresolved_emitted_ids": [
                f"0x{resource_id:x}"
                for resource_id in TOPOLOGY_UNRESOLVED_RESOURCE_IDS
            ],
            "unresolved_ids_registered_in_exact_primary_registry": False,
            "runtime_topology_selector": "UNKNOWN",
            "result": (
                "BIMC_MPU0..3 absence from static policy arrays does not mean "
                "unconfigured; the exact TZ memory-lock path programs them dynamically."
            ),
        },
        "master_mpu_boot_initialization": {
            "boot_function": "0x1c0a40f8",
            "initializer": "0x1c0ace70",
            "selectors": master_selectors,
            "bimc_mpu_initialized_by_this_loop": False,
        },
        "controller_aperture_policy": controller_policy,
        "xbl_boundary": xbl_boundary,
        "secure_config_lock_boundary": {
            "static_config_initial_word": "0x0001c800",
            "comparative_secure_config_write_disable_mask_requested_initially": False,
            "xpu3_init_dereferences_second_config_argument": False,
            "restore_preserves_control_mask": "0x00000002",
            "reset_preserves_control_mask": "0x00000002",
            "runtime_control_register_readback": "UNKNOWN",
            "conclusion": (
                "The inspected TZ caller is consistent with secure-world dynamic "
                "mutability, but the final boot/runtime hardware lock bit is not proved."
            ),
        },
        "devcfg_xpu_control": {
            "device_path": devcfg_xpu["device_path"],
            "property_name": devcfg_xpu["property_name"],
            "value": devcfg_xpu["value"],
            "property_vaddr": f"0x{int(devcfg_xpu['property_vaddr']):x}",
        },
        "code_pins": {
            "trustzone_functions": tz_functions,
            "trustzone_instruction_words": tz_instructions,
            "qhee_hyp_functions": hyp_functions,
            "qhee_hyp_instruction_words": hyp_instructions,
        },
        "comparative_source": COMPARATIVE_SOURCE,
        "claims": {
            "PROVED": [
                (
                    "Exact QHEE registers SMC 0x02000c16 at 0x85723b90 and "
                    "routes it to a local AC mapping wrapper without directly "
                    "calling QHEE's generic TZ SMC wrapper."
                ),
                (
                    "Exact TZ separately registers SMC 0x02000c16 and its "
                    "assignment/lock chain reaches dynamic BIMC MPU reconfiguration."
                ),
                (
                    "Exact TZ dynamic topology code emits registered resources "
                    "BIMC_MPU0..3 and, in some cases, LLCC_BROADCAST_MPU."
                ),
                (
                    "The exact HLOS-visible XPU toggle SMC has a zero-entry "
                    "disable whitelist; its enable path restores only a registered XPU."
                ),
                (
                    "Both embedded TZ static-policy branches cover all four "
                    "remapper and BIMC configuration apertures with TZ-owned "
                    "MEMNOC_MS_MPU and CNOC_SNOC_MS_MPU records that contain no HLOS VMID grant."
                ),
                (
                    "The boot master-MPU loop initializes CNOC_AOSS_MPU, "
                    "ANOC2_MPU, and MSS_NAV_MPU, not BIMC_MPU0..3."
                ),
                (
                    "The exact TZ RPM-online handler is a single RET and the "
                    "exact app-region notification handler does not directly call BIMC/XPU code."
                ),
            ],
            "SUPPORTED": [
                (
                    "On the production A90 path QHEE's same-ID intercept handles "
                    "HLOS hyp_assign before the separate TZ fallback implementation."
                ),
                (
                    "The controller apertures are effectively inaccessible to EL1 "
                    "under the embedded production policy; exact runtime register "
                    "readback is still absent."
                ),
                (
                    "The inspected static-config construction does not request the "
                    "comparative secure-config-write-disable field, consistent with "
                    "later secure-world lock/unlock operations."
                ),
            ],
            "HYPOTHESIS": [
                (
                    "The final DRAM channel/bank/rank transform, if configurable, "
                    "is owned by a block downstream of the currently identified apertures."
                ),
            ],
            "REFUTED": [
                "BIMC_MPU0..3 are unconfigured merely because they are absent from the two static TZ policy arrays.",
                "The QHEE hyp_assign handler itself is a direct TZ BIMC/XPU programming primitive.",
                "The named RPM-region QHEE/TZ service mutates an XPU in this exact A90 TZ build.",
                "SMC 0x02000c23 provides HLOS a usable XPU-disable primitive on this exact build.",
                "Literal BIMC addresses in the XBL file alone prove that main XBL code programs their policy.",
            ],
            "UNKNOWN": [
                "Final post-boot BIMC/XPU control and region-register values.",
                "The runtime topology selector and whether unresolved IDs 0x51-0x54 execute on this target.",
                "The exact final physical-address-to-DRAM channel/bank/rank/row transform owner and ordering.",
                "Whether a second protection check occurs after the final DRAM transform.",
                "Any physical-to-DRAM alias or protected-memory isolation bypass.",
            ],
        },
        "classification": "CLASS_A_OR_B_CANDIDATE_CONTROLLER_APERTURES_ONLY_NO_BYPASS",
        "vulnerability_assessment": {
            "evidence_for": [
                "Secure world dynamically programs BIMC MPU resources during memory ownership changes.",
                "A physical-to-DRAM transform remains unidentified and could be downstream.",
            ],
            "evidence_against": [
                "All known remapper/BIMC configuration apertures are covered by two branch-invariant TZ-owned policies.",
                "The only identified HLOS-visible XPU toggle cannot disable any XPU because its exact whitelist count is zero.",
                "QHEE hyp_assign adds an independent ownership/stage-2/SMMU enforcement layer.",
            ],
            "critical_unknowns": [
                "Runtime register readback",
                "Final DRAM transform block",
                "Post-transform protection ordering",
            ],
            "current_result": "NO_SECURITY_BOUNDARY_BYPASS_OBSERVED",
        },
    }


def inventory(
    xbl_path: Path,
    tz_path: Path,
    hyp_path: Path,
    devcfg_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    paths = {
        "xbl": xbl_path,
        "trustzone": tz_path,
        "hyp": hyp_path,
        "devcfg": devcfg_path,
    }
    blobs = {label: path.read_bytes() for label, path in paths.items()}
    public_inputs: dict[str, object] = {}
    private_inputs: dict[str, object] = {}
    for label, path in paths.items():
        metadata = verify_pinned_bytes(label, blobs[label], PINS[label])
        public_inputs[label] = {"filename": path.name, **metadata}
        private_inputs[label] = {
            "path": str(path.resolve()),
            "filename": path.name,
            **metadata,
        }

    analysis = analyze(
        blobs["xbl"], blobs["trustzone"], blobs["hyp"], blobs["devcfg"]
    )
    common = {
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        **analysis,
    }
    private_result = {
        "schema": "sdm855-xpu-initializer-inventory-private-v1",
        "inputs": private_inputs,
        **copy.deepcopy(common),
    }
    public_result = {
        "schema": "sdm855-xpu-initializer-inventory-public-v1",
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
    parser.add_argument("--tz", type=Path, default=firmware / "tz--sdd5.bin")
    parser.add_argument("--hyp", type=Path, default=firmware / "hyp--sdd33.bin")
    parser.add_argument(
        "--devcfg", type=Path, default=firmware / "devcfg--sdd22.bin"
    )
    parser.add_argument(
        "--private-output",
        type=Path,
        default=root
        / "evidence/private/010-xpu-initializer-inventory-20260825-01.json",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=root
        / "evidence/manifests/010-xpu-initializer-inventory-20260825-01.manifest.json",
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
        args.xbl.resolve(), args.tz.resolve(), args.hyp.resolve(), args.devcfg.resolve()
    )
    private_encoded = json_bytes(private_result)
    public_result["private_record"] = {
        "filename": private_output.name,
        "size": len(private_encoded),
        "sha256": sha256(private_encoded),
        "git_ignored": True,
    }
    public_encoded = json_bytes(public_result)

    if args.replace:
        atomic_replace(private_output, private_encoded, 0o600)
        atomic_replace(manifest_output, public_encoded, 0o644)
    else:
        private_output.parent.mkdir(parents=True, exist_ok=True)
        manifest_output.parent.mkdir(parents=True, exist_ok=True)
        write_new(private_output, private_encoded, 0o600)
        write_new(manifest_output, public_encoded, 0o644)
    print(private_output)
    print(manifest_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
