#!/usr/bin/env python3
"""Recover the exact A90 XBL raw-dump entry and full-catalog gates.

Host-only and read-only.  This tool pins the retained SM-A908N XBL, verifies
the instruction words that read Samsung's parameter record and branch into the
raw-dump catalog, resolves two shared-function imports through the exact XBL
producer table, and emits a truth table for the resulting gate.

It does not contact a device, alter ``param``, execute firmware, issue an SMC,
or emit proprietary firmware bytes.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import itertools
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.sm8150_shrm_dump_export_inventory import (
        ElfImage,
        _decode_aarch64_add_immediate,
        _decode_aarch64_adrp,
        _decode_aarch64_bl,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from sm8150_shrm_dump_export_inventory import (  # type: ignore
        ElfImage,
        _decode_aarch64_add_immediate,
        _decode_aarch64_adrp,
        _decode_aarch64_bl,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_DIR = (
    REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
)
DEFAULT_XBL = FIRMWARE_DIR / "xbl--sdb1.bin"
DEFAULT_PRIVATE_OUTPUT = (
    REPO_ROOT
    / "evidence/private/verification-005-xbl-rawdump-gate-static-20260825-01.json"
)
DEFAULT_PUBLIC_OUTPUT = (
    REPO_ROOT
    / "evidence/manifests/verification-005-xbl-rawdump-gate-static-20260825-01.manifest.json"
)

KERNEL_ROOT = Path(
    "/mnt/android-lab-sd/inputs/kernel_source/"
    "SM-A908N_KOR_12_Opensource_13272/Kernel"
)
SOURCE_PINS: Mapping[str, tuple[Path, str]] = {
    "sec_param_h": (
        KERNEL_ROOT / "include/linux/samsung/sec_param.h",
        "58b6963e9e45e8b60fa41a5997f4e2ca8f8a0002e302a8a4df765f345b6b892f",
    ),
    "sec_param_c": (
        KERNEL_ROOT / "drivers/samsung/sec_param.c",
        "86c03620a8c517dd3111006a15bc777a5d7cfedff75eebc4004e8d0e1bcd99c2",
    ),
    "sec_debug_h": (
        KERNEL_ROOT / "include/linux/samsung/debug/sec_debug.h",
        "893a8747793e2b5aa6457295e2bace268763d4bb251a1567504d55d209381db3",
    ),
    "sec_debug_c": (
        KERNEL_ROOT / "drivers/samsung/debug/sec_debug.c",
        "21e36f47deba1cf775928f4117443da3a88dc8316315f985676d93221a9f14c9",
    ),
    "msm_poweroff_c": (
        KERNEL_ROOT / "drivers/power/reset/msm-poweroff.c",
        "0a2b20ecc358936d5a55a9936210345823ffe767768e9287a916502a3abc3d79",
    ),
}

XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

PARAM_RECORD_PHYSICAL = 0x00900000
PARAM_DEBUG_OFFSET = 0x000
PARAM_FORCE_UPLOAD_OFFSET = 0x3F4
PARAM_FMM_LOCK_OFFSET = 0x3FC
PARAM_DUMP_SINK_OFFSET = 0x400

KERNEL_DEBUG_LOW = 0x574F4C44
KERNEL_DEBUG_MID = 0x44494D44
KERNEL_DEBUG_HIGH = 0x47494844
ANDROID_DEBUG_LOW = 0x4F4C
ANDROID_DEBUG_MID = 0x494D
ANDROID_DEBUG_HIGH = 0x4948
FORCE_UPLOAD_ENABLED = 5
FMM_LOCK_MAGIC = 0x464D4F4E
DUMP_SINK_USB = 0
DUMP_SINK_SDCARD = 0x73646364
DUMP_SINK_BOOTDEV = 0x42544456

RESTART_REASON_SEC_DEBUG_MODE = 0x776655EE
SBL_DLOAD_MODE_BIT_MASK = 0x10
TZ_ALLOWS_MEM_DUMP_CMD = 0x82000310
QUEST_DDR_CAUSE_PAIR_MASKED = 0xC8515313

ENTRY_GATE_START = 0x14901A7C
ENTRY_GATE_END = 0x14901DC4
DLOAD_ENTRY = 0x14902CB8
CATALOG_BUILDER = 0x14917740
CATALOG_CONSUMER = 0x14917C60
PRIMARY_LOOP = 0x14917CA8
TZ_ALLOW_WRAPPER = 0x14918410
SHARED_TABLE_PRODUCER_START = 0x14844580
SHARED_TABLE_PRODUCER_END = 0x14844DA8
SEC_DEBUG_RESTART_CHECK = 0x1482AFE8
TZ_ALLOW_SMC_TARGET = 0x14843D50
OUTER_DLOAD_GATE_START = 0x14829F28
OUTER_DLOAD_GATE_END = 0x14829F44
SAVED_COOKIE_READ_CLEAR_START = 0x14829A94
SAVED_COOKIE_READ_CLEAR_END = 0x14829B28

CODE_PINS = (
    ("entry_gate", ENTRY_GATE_START, ENTRY_GATE_END,
     "91a6f7cfe13a8a45be8bfc471a27538e0914a3fa2fcc3f9dfacf51e0a328605e"),
    ("outer_dload_gate", OUTER_DLOAD_GATE_START, OUTER_DLOAD_GATE_END,
     "f0082ec1d4ac183dfce85e0673e22c765e0e35eb18863db9bf4abb92eea2ee40"),
    ("saved_cookie_read_clear", SAVED_COOKIE_READ_CLEAR_START,
     SAVED_COOKIE_READ_CLEAR_END,
     "e83df79752206af6cdb6d61e4e122a08b68e38e0ca8e913f26a858473ccda6ed"),
    ("rawdump_segment_entry", 0x14900010, 0x149000A8,
     "3f3cc08aee409dcb578b48f68a8834f44975b24522ef7fd0c7ef5cc4606b85ab"),
    ("dload_entry", DLOAD_ENTRY, 0x14902CE8,
     "9b4cc75011cd7be22a5f4bd3c1b5981172a710b0b00315a922679d8b41505741"),
    ("catalog_gate", 0x14917C8C, PRIMARY_LOOP,
     "6a90a331b7769ab9e1dc92aa13183528e360e42cce0b9ece03e367c70609efb5"),
    ("tz_allow_wrapper", TZ_ALLOW_WRAPPER, 0x14918454,
     "72f3af2f1a5c92a4d61b0b6727164afd061ab9bc998005bdfb87f330052205b5"),
    ("shared_table_producer", SHARED_TABLE_PRODUCER_START,
     SHARED_TABLE_PRODUCER_END,
     "7bc8503c02b3890d9f767ced7ee65fb787a8aa62a746dc9344d04739f7f8e502"),
    ("sec_debug_restart_check", SEC_DEBUG_RESTART_CHECK, 0x1482B008,
     "e10badcb567a326ac66e586c6307fa48cb0f067202f7f65b45193c4cf17da941"),
    ("tz_allow_smc_target", TZ_ALLOW_SMC_TARGET, 0x14843D98,
     "8f99eab91f09274b5624892dfeb427fd67b46d65a2ba1de7e70620bb4d92e071"),
    ("dump_sink_decode", 0x14905E4C, 0x14905ECC,
     "27f60ee4e6ff055351d694dbf39234b2c916f3d7da65850b3794e522b3ecae57"),
)

# These are the load/compare/branch instructions carrying the gate.  Pinning
# them prevents a nearby matching string or an unrelated constant from being
# promoted to the exact control flow.
WORD_PINS: Mapping[int, int] = {
    0x14829AA8: 0x52860013,
    0x14829AAC: 0x72A03FB3,  # x19 = saved-cookie address 0x01fd3000
    0x14829ABC: 0xB9400268,
    0x14829AC0: 0x121C0503,  # saved cookie & 0x30
    0x14829AC8: 0x340001A3,
    0x14829AEC: 0x320003E0,
    0x14829AF0: 0x121A7528,  # clear consumed bits 4 and 5
    0x14829AF4: 0xB9000268,
    0x14829F2C: 0x97FFFEDA,  # read-and-clear saved cookie
    0x14829F34: 0x3500006D,  # cookie result selects dload path
    0x14829F38: 0x9400042C,  # SEC_DEBUG restart reason fallback
    0x14829F3C: 0x340005E0,  # neither trigger takes non-dload continuation
    0x14901AA4: 0x52A01213,  # w19 = 0x00900000
    0x14901AC4: 0x910FF263,  # x3 = param + 0x3fc
    0x14901AD8: 0x97FFF9A3,  # fixed four-byte read
    0x14901AE0: 0x5289E9CA,
    0x14901AE4: 0x72A8C9AA,  # w10 = FMM lock magic
    0x14901AE8: 0x6B0A013F,
    0x14901AEC: 0x540000E1,  # FMM mismatch continues; equality denies
    0x14901B20: 0xAA1303E3,  # x3 = param + 0
    0x14901B24: 0x97FFF990,
    0x14901B28: 0x910FD263,  # x3 = param + 0x3f4
    0x14901B3C: 0x97FFF98A,
    0x14901B50: 0xB9401FEB,
    0x14901B54: 0x5289888C,
    0x14901B58: 0x72AAE9EC,  # w12 = DLOW
    0x14901B5C: 0x6B0C017F,
    0x14901B60: 0x540000E1,  # non-LOW takes vendor-allow path
    0x14901B64: 0xB9401BE8,
    0x14901B68: 0x7100151F,  # force_upload_flag == 5
    0x14901B6C: 0x540005E1,
    0x14901B7C: 0x320003E8,  # vendor_allow = 1
    0x14901B84: 0xB9011AC8,
    0x14901C28: 0x94005BC8,  # alternate three-predicate key path
    0x14901C34: 0x97FFF9B0,
    0x14901C40: 0x97FFF9A5,
    0x14901C7C: 0x2A1F03E8,  # vendor_allow = 0
    0x14901C64: 0x940059EB,  # TZ allows-memory-dump wrapper
    0x14901C6C: 0x340000CE,
    0x14901C70: 0xB9411AC4,
    0x14901C74: 0x35000124,  # TZ allow OR vendor_allow reaches dload
    0x14901C90: 0xB9411AD1,
    0x14901C94: 0x34000931,  # both false skips upload
    0x14901CC8: 0x940003FC,  # BL 0x14902cb8
    0x14917C90: 0x97FFA1A9,  # boot_dload_read_saved_cookie
    0x14917C9C: 0x37200060,  # bit 4 enters full catalog
    0x14917CA0: 0x97FFA28D,  # SEC_DEBUG restart override
    0x14917CA4: 0x34001D20,  # false skips primary 26-record table
    0x1482AFF0: 0x528ABDC9,
    0x1482AFF4: 0x72AEECC9,  # restart reason 0x776655ee
    0x1482AFF8: 0xB9400108,
    0x1482AFFC: 0x6B09011F,
    0x1482B000: 0x1A9F17E0,
    0x14843D5C: 0x52806208,
    0x14843D60: 0x72B04008,  # SMC 0x82000310
    0x14843D84: 0x97F9A89F,
    0x14905E68: 0x52888AC6,
    0x14905E6C: 0x72A84A86,  # dump sink bootdev magic
    0x14905E78: 0x6B06011F,
    0x14905E80: 0x528C6C87,
    0x14905E84: 0x72AE6C87,  # dump sink SD-card magic
    0x14905E88: 0x6B07011F,
}

STRINGS: Mapping[int, str] = {
    0x1481DC90: "XBLRamDump Image Loaded, Delta",
    0x1481E140: "boot_dload.c",
    0x1494BCDF: "@ FMM Lock is On, Ramdump is not Allowed! Hard Reset...",
    0x1494BD17: "DebugLevel : %d, ForceUploadFlag : %d",
    0x1494BD3D: "FORCE UPLOAD is enabled!",
    0x1494BD56: "edl + pwr + up, debug level low, but go to upload ",
    0x1494BD89: "@ RAM dump by hard reset ? Skip EDL.",
    0x1494BDAE: "@ Debug level LOW && ram dump not allowed, skip dump summary !",
    0x1494BDED: "AST_UPLOAD",
    0x1494BE2F: "@ Continue boot by Debug level LOW",
}

PROXY_PRIMARY_SOURCES = (
    {
        "role": "shared-function ABI and TZ_ALLOWS_MEM_DUMP_CMD name",
        "repository": "arzekrasr/BOOT.XF.4.1",
        "commit": "53a3bb52a45ca92b6bf2d1aa0ba6936d9ff156bc",
        "path": "QcomPkg/XBLLoader/boot_fastcall_tz.h",
        "url": "https://github.com/arzekrasr/BOOT.XF.4.1/blob/53a3bb52a45ca92b6bf2d1aa0ba6936d9ff156bc/QcomPkg/XBLLoader/boot_fastcall_tz.h",
        "exact_target_source": False,
    },
    {
        "role": "Qualcomm XBLRamDump control-flow comparison",
        "repository": "arzekrasr/BOOT.XF.4.1",
        "commit": "53a3bb52a45ca92b6bf2d1aa0ba6936d9ff156bc",
        "path": "QcomPkg/SocPkg/Library/XBLRamDumpLib/XBLRamDump.c",
        "url": "https://github.com/arzekrasr/BOOT.XF.4.1/blob/53a3bb52a45ca92b6bf2d1aa0ba6936d9ff156bc/QcomPkg/SocPkg/Library/XBLRamDumpLib/XBLRamDump.c",
        "exact_target_source": False,
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ParamPrefix(ctypes.Structure):
    """Exact arm64 layout through Samsung's dump-sink field."""

    _fields_ = [
        ("debuglevel", ctypes.c_uint32),
        ("uartsel", ctypes.c_uint32),
        ("rory_control", ctypes.c_uint32),
        ("product_device", ctypes.c_uint32),
        ("reserved1", ctypes.c_uint32),
        ("cp_debuglevel", ctypes.c_uint32),
        ("reserved2", ctypes.c_uint32),
        ("sapa_or_reserved3", ctypes.c_uint32 * 3),
        ("normal_poweroff_or_reserved4", ctypes.c_uint32),
        ("wireless_ic_or_reserved5", ctypes.c_uint32),
        ("used0_to_used4", ctypes.c_char * 400),
        ("wireless_charging_or_reserved6", ctypes.c_uint32),
        ("afc_disable_or_reserved7", ctypes.c_uint32),
        ("cp_reserved_mem", ctypes.c_uint32),
        ("used5", ctypes.c_char * 4),
        ("used6", ctypes.c_char * 4),
        ("reserved8", ctypes.c_char * 8),
        ("used7", ctypes.c_char * 16),
        ("api_gpio_test", ctypes.c_uint32),
        ("api_gpio_test_result", ctypes.c_char * 256),
        ("reboot_recovery_cause", ctypes.c_char * 256),
        ("user_partition_flashed", ctypes.c_uint32),
        ("force_upload_flag", ctypes.c_uint32),
        ("cp_reserved_mem_backup", ctypes.c_uint32),
        ("FMM_lock", ctypes.c_uint32),
        ("dump_sink", ctypes.c_uint32),
    ]


@dataclass(frozen=True)
class GateInputs:
    fmm_locked: bool
    debug_low: bool
    force_upload_enabled: bool
    three_key_override: bool
    tz_allows_memory_dump: bool
    saved_dload_cookie_mask_0x30: bool = True
    quest_ddr_special_cause: bool = False
    dload_cookie_full_bit: bool = True
    sec_debug_restart_reason: bool = True


def evaluate_gate(inputs: GateInputs) -> dict[str, object]:
    """Evaluate the branch formula proved by the pinned instructions."""
    outer_dload_trigger = (
        inputs.saved_dload_cookie_mask_0x30
        or inputs.sec_debug_restart_reason
    )
    vendor_allow = (
        (not inputs.debug_low)
        or inputs.force_upload_enabled
        or inputs.three_key_override
    )
    if inputs.fmm_locked:
        inner_entry = False
        entry_reason = "FMM_LOCK_HARD_RESET"
    elif inputs.quest_ddr_special_cause:
        inner_entry = False
        entry_reason = "QUEST_DDR_SPECIAL_PATH"
    else:
        inner_entry = vendor_allow or inputs.tz_allows_memory_dump
        entry_reason = (
            "VENDOR_ALLOW"
            if vendor_allow
            else "TZ_ALLOWS_MEMORY_DUMP"
            if inputs.tz_allows_memory_dump
            else "LOW_DEBUG_AND_TZ_DENY_SKIP"
        )
    entry = outer_dload_trigger and inner_entry
    full_catalog = entry and (
        inputs.dload_cookie_full_bit or inputs.sec_debug_restart_reason
    )
    return {
        **asdict(inputs),
        "outer_dload_trigger_present": outer_dload_trigger,
        "vendor_allow": vendor_allow,
        "rawdump_app_gate_allows": inner_entry,
        "enters_dload_call_chain": entry,
        "entry_reason": entry_reason,
        "registers_primary_26_record_catalog": full_catalog,
        "shrm_descriptor_registered": full_catalog,
    }


def dump_sink_label(value: int) -> str:
    if value == DUMP_SINK_SDCARD:
        return "SDCARD"
    if value == DUMP_SINK_BOOTDEV:
        return "BOOTDEV_INTERNAL"
    return "USB_DEFAULT"


def _validate_param_layout() -> dict[str, object]:
    offsets = {
        "debuglevel": ParamPrefix.debuglevel.offset,
        "force_upload_flag": ParamPrefix.force_upload_flag.offset,
        "FMM_lock": ParamPrefix.FMM_lock.offset,
        "dump_sink": ParamPrefix.dump_sink.offset,
    }
    expected = {
        "debuglevel": PARAM_DEBUG_OFFSET,
        "force_upload_flag": PARAM_FORCE_UPLOAD_OFFSET,
        "FMM_lock": PARAM_FMM_LOCK_OFFSET,
        "dump_sink": PARAM_DUMP_SINK_OFFSET,
    }
    if offsets != expected:
        raise ValueError(f"derived param offsets changed: {offsets} != {expected}")
    return {
        "record_physical_base_used_by_xbl": f"0x{PARAM_RECORD_PHYSICAL:08x}",
        "derived_offsets": {key: f"0x{value:03x}" for key, value in offsets.items()},
        "absolute_read_addresses": {
            key: f"0x{PARAM_RECORD_PHYSICAL + value:08x}"
            for key, value in offsets.items()
        },
        "values": {
            "kernel_debug_low": f"0x{KERNEL_DEBUG_LOW:08x}",
            "kernel_debug_mid": f"0x{KERNEL_DEBUG_MID:08x}",
            "kernel_debug_high": f"0x{KERNEL_DEBUG_HIGH:08x}",
            "force_upload_enabled": FORCE_UPLOAD_ENABLED,
            "fmm_lock_magic": f"0x{FMM_LOCK_MAGIC:08x}",
            "dump_sink_usb_default": f"0x{DUMP_SINK_USB:08x}",
            "dump_sink_sdcard": f"0x{DUMP_SINK_SDCARD:08x}",
            "dump_sink_bootdev": f"0x{DUMP_SINK_BOOTDEV:08x}",
        },
    }


def _validate_sources() -> list[dict[str, object]]:
    requirements: Mapping[str, tuple[str, ...]] = {
        "sec_param_h": (
            "unsigned int debuglevel;",
            "unsigned int force_upload_flag;",
            "unsigned int FMM_lock;",
            "unsigned int dump_sink;",
            "#define FMMLOCK_MAGIC_NUM\t0x464D4F4E",
        ),
        "sec_param_c": (
            'static const char *param_name = "/dev/block/bootdevice/by-name/param";',
            "sched_sec_param_data.offset = SEC_PARAM_FILE_OFFSET;",
        ),
        "sec_debug_h": (
            "#define KERNEL_SEC_DEBUG_LEVEL_LOW\t(0x574F4C44)",
            "#define KERNEL_SEC_DEBUG_LEVEL_MID\t(0x44494D44)",
            "#define KERNEL_SEC_DEBUG_LEVEL_HIGH\t(0x47494844)",
            "#define DUMP_SINK_TO_SDCARD 0x73646364",
            "#define DUMP_SINK_TO_BOOTDEV 0x42544456",
        ),
        "sec_debug_c": (
            "sec_debug_set_upload_magic(RESTART_REASON_SEC_DEBUG_MODE);",
            "sec_debug_set_upload_cause(UPLOAD_CAUSE_NON_SECURE_WDOG_BARK);",
            "set_dload_mode(on);",
        ),
        "msm_poweroff_c": (
            "#define SCM_DLOAD_FULLDUMP\t\t0X10",
            "static int dload_type = SCM_DLOAD_FULLDUMP;",
            "module_param_call(download_mode, dload_set, param_get_int,",
        ),
    }
    result = []
    for name, (path, expected_hash) in SOURCE_PINS.items():
        data = path.read_bytes()
        actual = sha256(data)
        if actual != expected_hash:
            raise ValueError(f"{name} SHA-256 is {actual}, expected {expected_hash}")
        text = data.decode("utf-8")
        missing = [value for value in requirements[name] if value not in text]
        if missing:
            raise ValueError(f"{name} lacks required source statements: {missing}")
        result.append(
            {
                "name": name,
                "path": str(path),
                "sha256": actual,
                "required_statements_present": True,
            }
        )
    return result


def _validate_code(image: ElfImage) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    code = []
    for name, start, end, expected in CODE_PINS:
        raw = image.read_vaddr(start, end - start)
        actual = sha256(raw)
        if actual != expected:
            raise ValueError(f"{name} code SHA-256 is {actual}, expected {expected}")
        code.append(
            {
                "name": name,
                "start": f"0x{start:x}",
                "end_exclusive": f"0x{end:x}",
                "size": end - start,
                "sha256": actual,
            }
        )
    words = []
    for pc, expected in WORD_PINS.items():
        actual = image.u32(pc)
        if actual != expected:
            raise ValueError(
                f"instruction at 0x{pc:x} is 0x{actual:08x}, expected 0x{expected:08x}"
            )
        words.append({"pc": f"0x{pc:x}", "word": f"0x{actual:08x}"})
    for vaddr, expected in STRINGS.items():
        if image.cstring(vaddr) != expected:
            raise ValueError(f"gate string at 0x{vaddr:x} changed")
    return code, words


def _validate_calls(image: ElfImage) -> list[dict[str, object]]:
    calls = (
        (0x14829F2C, 0x14829A94, "outer_gate_to_saved_cookie_read_clear"),
        (0x14829F38, SEC_DEBUG_RESTART_CHECK, "outer_gate_to_restart_reason_check"),
        (0x14901CC8, DLOAD_ENTRY, "entry_gate_to_dload"),
        (0x14902CC4, CATALOG_BUILDER, "dload_to_catalog_builder"),
        (0x1491777C, CATALOG_CONSUMER, "builder_to_catalog_consumer"),
        (0x14901C64, TZ_ALLOW_WRAPPER, "entry_gate_to_tz_allow_wrapper"),
    )
    result = []
    for pc, expected, name in calls:
        word = image.u32(pc)
        target = _decode_aarch64_bl(word, pc)
        if target != expected:
            raise ValueError(f"{name} target 0x{target:x} != 0x{expected:x}")
        result.append(
            {"name": name, "pc": f"0x{pc:x}", "target": f"0x{target:x}"}
        )
    return result


def _producer_target(
    image: ElfImage,
    adrp_pc: int,
    add_pc: int,
    register: int,
    store_pc: int,
    store_word: int,
    table_offset: int,
) -> dict[str, object]:
    rd, page = _decode_aarch64_adrp(image.u32(adrp_pc), adrp_pc)
    add_rd, add_rn, immediate = _decode_aarch64_add_immediate(image.u32(add_pc))
    if (rd, add_rd, add_rn) != (register, register, register):
        raise ValueError("producer target register chain changed")
    if image.u32(store_pc) != store_word:
        raise ValueError(f"producer table store at 0x{store_pc:x} changed")
    return {
        "table_offset": f"0x{table_offset:03x}",
        "producer_adrp_pc": f"0x{adrp_pc:x}",
        "producer_add_pc": f"0x{add_pc:x}",
        "producer_store_pc": f"0x{store_pc:x}",
        "target": f"0x{page + immediate:x}",
    }


def _validate_import_resolution(image: ElfImage) -> dict[str, object]:
    saved_cookie = _producer_target(
        image, 0x148445C0, 0x148445FC, 2, 0x14844610, 0xA9060901, 0x068
    )
    restart_override = _producer_target(
        image, 0x14844CF8, 0x14844D40, 11, 0x14844D5C, 0xF902C10B, 0x580
    )
    if int(saved_cookie["target"], 16) != 0x14829A14:
        raise ValueError("saved-cookie producer target changed")
    if int(restart_override["target"], 16) != SEC_DEBUG_RESTART_CHECK:
        raise ValueError("SEC_DEBUG restart producer target changed")
    if image.u32(0x14900334) != 0x529E0D08 or image.u32(0x1490033C) != 0xF9400100:
        raise ValueError("saved-cookie consumer wrapper changed")
    if image.u32(0x149006D4) != 0x529EB008 or image.u32(0x149006DC) != 0xF9400100:
        raise ValueError("restart-override consumer wrapper changed")
    return {
        "boot_dload_read_saved_cookie": saved_cookie,
        "sec_debug_restart_reason_override": restart_override,
        "restart_override_semantics": {
            "physical_address": "0x146bf65c",
            "required_value": f"0x{RESTART_REASON_SEC_DEBUG_MODE:08x}",
            "result": "true exactly when restart reason equals SEC_DEBUG_MODE",
        },
    }


def _truth_table() -> list[dict[str, object]]:
    rows = []
    for fmm, low, force, keys, tz in itertools.product((False, True), repeat=5):
        rows.append(
            evaluate_gate(
                GateInputs(
                    fmm_locked=fmm,
                    debug_low=low,
                    force_upload_enabled=force,
                    three_key_override=keys,
                    tz_allows_memory_dump=tz,
                )
            )
        )
    return rows


def analyze(xbl_data: bytes) -> dict[str, object]:
    if len(xbl_data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(xbl_data)}, expected {XBL_SIZE}")
    actual_hash = sha256(xbl_data)
    if actual_hash != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 is {actual_hash}, not the exact pin")
    image = ElfImage(xbl_data)
    code_pins, word_pins = _validate_code(image)
    calls = _validate_calls(image)
    imports = _validate_import_resolution(image)
    sources = _validate_sources()
    param = _validate_param_layout()

    debug_only = evaluate_gate(
        GateInputs(
            fmm_locked=False,
            debug_low=False,
            force_upload_enabled=False,
            three_key_override=False,
            tz_allows_memory_dump=False,
            saved_dload_cookie_mask_0x30=True,
            dload_cookie_full_bit=True,
            sec_debug_restart_reason=True,
        )
    )
    current = evaluate_gate(
        GateInputs(
            fmm_locked=False,
            debug_low=True,
            force_upload_enabled=False,
            three_key_override=False,
            tz_allows_memory_dump=False,
            saved_dload_cookie_mask_0x30=True,
            dload_cookie_full_bit=True,
            sec_debug_restart_reason=True,
        )
    )
    orderly_mid_boot = evaluate_gate(
        GateInputs(
            fmm_locked=False,
            debug_low=False,
            force_upload_enabled=False,
            three_key_override=False,
            tz_allows_memory_dump=False,
            saved_dload_cookie_mask_0x30=False,
            dload_cookie_full_bit=False,
            sec_debug_restart_reason=False,
        )
    )
    return {
        "schema": "sdm855-xbl-rawdump-gate-static-v1",
        "mode": "HOST_ONLY_READ_ONLY",
        "input": {
            "filename": DEFAULT_XBL.name,
            "size": len(xbl_data),
            "sha256": actual_hash,
            "pin_verified": True,
        },
        "device_access": False,
        "partition_write": False,
        "smc_executed": False,
        "firmware_bytes_emitted": False,
        "code_pins": code_pins,
        "instruction_pins": word_pins,
        "call_chain": calls,
        "param_record": param,
        "source_provenance": {
            "exact_samsung_kernel_sources": sources,
            "non_exact_qualcomm_proxy_sources": list(PROXY_PRIMARY_SOURCES),
        },
        "outer_dload_selection": {
            "formula": (
                "(saved_dload_cookie & 0x30) != 0 or "
                "restart_reason == 0x776655ee"
            ),
            "saved_cookie_address": "0x01fd3000",
            "consumed_cookie_mask": "0x30",
            "cookie_semantics": (
                "the exact main XBL path reads bits 4/5 and clears them before "
                "continuing; absence of both cookie bits and SEC_DEBUG restart "
                "reason takes the non-dload continuation"
            ),
            "scope": (
                "this is the outer main-XBL selection gate; the debug/FMM/TZ "
                "formula below is inside the separately mapped XBLRamDump image"
            ),
        },
        "entry_gate": {
            "formula": (
                "not FMM_locked and not QUEST_DDR_special and "
                "((debug != LOW) or (force_upload_flag == 5) or "
                "three_key_override or TZ_ALLOWS_MEM_DUMP)"
            ),
            "fmm_denial": {
                "param_offset": f"0x{PARAM_FMM_LOCK_OFFSET:03x}",
                "deny_value": f"0x{FMM_LOCK_MAGIC:08x}",
            },
            "vendor_allow": {
                "formula": "debug != LOW or force_upload_flag == 5 or three_key_override",
                "debug_low": f"0x{KERNEL_DEBUG_LOW:08x}",
                "force_upload_enabled": FORCE_UPLOAD_ENABLED,
            },
            "tz_permission_query": {
                "smc_id": f"0x{TZ_ALLOWS_MEM_DUMP_CMD:08x}",
                "executed_by_tool": False,
                "control_flow_role": (
                    "sufficient when vendor_allow is false; not required for entry "
                    "when vendor_allow is true"
                ),
            },
            "quest_ddr_special_exclusion": (
                "(upload_cause | 1) == 0xc8515313 takes the dedicated Quest DDR path"
            ),
            "truth_table": _truth_table(),
        },
        "full_catalog_gate": {
            "formula": "saved_dload_cookie bit 4 or restart_reason == 0x776655ee",
            "saved_cookie_full_dump_bit": f"0x{SBL_DLOAD_MODE_BIT_MASK:02x}",
            "restart_reason": f"0x{RESTART_REASON_SEC_DEBUG_MODE:08x}",
            "resolved_imports": imports,
            "primary_loop": f"0x{PRIMARY_LOOP:x}",
            "shrm_record_index": 19,
        },
        "watchdog_join": {
            "exact_kernel_source": (
                "sec_debug_prepare_for_wdog_bark_reset writes SEC_DEBUG_MODE and "
                "NON_SECURE_WDOG_BARK; sec_debug_set_upload_magic(nonzero) calls "
                "set_dload_mode(1); msm-poweroff uses full-dump type 0x10"
            ),
            "consequence": (
                "the proved watchdog path supplies both full-dump cookie bit 4 and "
                "the SEC_DEBUG_MODE catalog override while download_mode remains 1"
            ),
        },
        "dump_sink": {
            "param_offset": f"0x{PARAM_DUMP_SINK_OFFSET:03x}",
            "usb_default": f"0x{DUMP_SINK_USB:08x}",
            "sdcard": f"0x{DUMP_SINK_SDCARD:08x}",
            "bootdev_internal": f"0x{DUMP_SINK_BOOTDEV:08x}",
            "selection": (
                "only exact SD-card or bootdev magic selects storage; every other "
                "value follows the USB-default branch"
            ),
            "live_value": "UNKNOWN_PENDING_PARAM_CAPTURE",
        },
        "evaluations": {
            "current_visible_state_with_fmm_zero_and_tz_deny": current,
            "watchdog_trigger_plus_debug_non_low_with_force_zero_and_tz_deny": debug_only,
            "orderly_boot_debug_non_low_without_outer_trigger": orderly_mid_boot,
        },
        "minimal_next_state": {
            "classification": "DEBUG_ONLY_SUFFICIENT_WHEN_OUTER_DUMP_TRIGGER_PRESENT",
            "change_debuglevel_to": f"0x{KERNEL_DEBUG_MID:08x}",
            "keep_force_upload_flag": f"0x{0:08x}",
            "keep_dump_sink": f"0x{DUMP_SINK_USB:08x}",
            "preconditions": [
                "byte-exact param partition capture and independent before/host/after hashes",
                "live FMM_lock is not 0x464d4f4e",
                "live dump_sink is USB default or is explicitly restored to its captured value",
                "download_mode remains 1",
                "a controlled watchdog/panic supplies an outer dump trigger only after host collection is ready",
            ],
        },
        "claims": {
            "PROVED": [
                "Exact XBL reads debuglevel, force_upload_flag and FMM_lock at offsets 0x0, 0x3f4 and 0x3fc of the same Samsung param record whose exact kernel-source layout has those offsets.",
                "FMM lock magic 0x464d4f4e hard-resets before the dload chain.",
                "When FMM is unlocked, non-LOW debug alone sets vendor_allow even with force_upload_flag zero and a negative TZ_ALLOWS_MEM_DUMP result.",
                "The full 26-record catalog, including SHRM record 19, is selected by saved dload cookie bit 4 or exact restart reason 0x776655ee.",
                "The exact watchdog source sets SEC_DEBUG_MODE and requests full-dump dload mode while the dload master is enabled.",
                "Main XBL selects its dload path only when saved cookie bits 4/5 are present or restart reason equals 0x776655ee; it consumes and clears saved cookie bits 4/5.",
                "Dump sink values 0x73646364 and 0x42544456 select SD card and internal boot device; other values use the USB-default branch.",
            ],
            "SUPPORTED": [
                "A debug-level-only experiment is the minimum persistent state change for the already-proved watchdog path; force_upload_flag need not be changed.",
                "An orderly reboot with MID but without a saved dload cookie, SEC_DEBUG restart reason, or key/FEDL override should take the ordinary non-dload continuation.",
            ],
            "REFUTED": [
                "Both debug level and force-upload must be enabled to reach the exact dload call chain.",
                "The TZ allows-memory-dump return is an unconditional prerequisite for reaching the vendor dload call when debug is non-LOW.",
                "An unidentified FMM cookie must be added: FMM is a deny lock whose exact param field and magic are known.",
            ],
            "UNKNOWN": [
                "Current byte values of FMM_lock and dump_sink until the param partition is captured.",
                "Whether a lower Sahara, XPU, TrustZone or transport check filters SHRM_MEM.BIN after catalog registration.",
                "Whether the USB host protocol permits selecting only SHRM_MEM.BIN instead of transferring the whole offered catalog.",
            ],
        },
        "classification": "DEBUG_ONLY_SUFFICIENT_WHEN_OUTER_DUMP_TRIGGER_PRESENT",
    }


def build_manifests(
    xbl_path: Path, xbl_data: bytes
) -> tuple[dict[str, object], dict[str, object]]:
    common = analyze(xbl_data)
    private = copy.deepcopy(common)
    private["schema"] = "sdm855-xbl-rawdump-gate-static-private-v1"
    private["input"]["path"] = str(xbl_path.resolve())
    public = copy.deepcopy(common)
    public["schema"] = "sdm855-xbl-rawdump-gate-static-public-v1"
    for entry in public["source_provenance"]["exact_samsung_kernel_sources"]:
        entry.pop("path", None)
    return private, public


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write(path: Path, data: bytes, mode: int, replace: bool) -> None:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xbl", type=Path, default=DEFAULT_XBL)
    parser.add_argument("--private-output", type=Path, default=DEFAULT_PRIVATE_OUTPUT)
    parser.add_argument("--public-output", type=Path, default=DEFAULT_PUBLIC_OUTPUT)
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data = args.xbl.read_bytes()
    private, public = build_manifests(args.xbl, data)
    print(f"CLASSIFICATION: {public['classification']}")
    print(f"ENTRY: {public['entry_gate']['formula']}")
    print(f"CATALOG: {public['full_catalog_gate']['formula']}")
    print("MINIMAL: debug=MID, force_upload_flag unchanged at zero")
    if args.replace:
        _write(args.private_output, _json_bytes(private), 0o600, True)
        _write(args.public_output, _json_bytes(public), 0o644, True)
        print(f"wrote {args.private_output}")
        print(f"wrote {args.public_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
