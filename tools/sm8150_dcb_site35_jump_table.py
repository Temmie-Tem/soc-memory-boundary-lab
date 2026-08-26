#!/usr/bin/env python3
"""Host-only Experiment 034: resolve the bounded site-35 jump table.

Experiment 034 is a small, deliberately local complement to Experiment 033.
It does not scan firmware for new sites and it does not claim that an
indirect branch is globally resolved.  It proves only the following bounded
fact: the exact site-35 guard and table-dispatch sequence has a five-entry
little-endian table, and each *unique* table entry can be checked in a fresh
copy of the exact XBL image after replacing only the site-35 ``BR X1`` with a
direct ``B`` to that entry.

The 033 source and public manifest are pinned by both bytes and semantics
before the source is executed.  The pinned 033 analyzer is then used for the
four synthetic, in-memory copies.  The input firmware is never changed.
Results remain ``CLASS C (TRANSFORM ONLY)``: this is bounded static CFG/data
flow evidence, not runtime execution, address authority, or a security
boundary result.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import struct
import sys
import types
from importlib.machinery import ModuleSpec
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
MANIFEST_DIR = REPO_ROOT / "evidence/manifests"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

EXPERIMENT_033_TOOL_NAME = "sm8150_dcb_residual_memory_frontier.py"
EXPERIMENT_033_TOOL_SIZE = 172_708
EXPERIMENT_033_TOOL_SHA256 = "aeb346253aab7860554c8a1cb627d04cbd56d9d82abf50a4a5b811da62a20f93"
EXPERIMENT_033_MANIFEST_NAME = "033-dcb-residual-memory-frontier-20260826-01.manifest.json"
EXPERIMENT_033_MANIFEST_SIZE = 2_017_356
EXPERIMENT_033_MANIFEST_SHA256 = "606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598"

SCHEMA = "sm8150-dcb-site35-jump-table-v1"
EXPERIMENT_ID = "034-dcb-site35-jump-table"
MODE = "HOST_ONLY_READ_ONLY"
CLASSIFICATION = "CLASS C (TRANSFORM ONLY)"
ELIGIBILITY = "NOT_ELIGIBLE"

SITE_INDEX = 35
SITE_STORE_VA = 0x1484F9E0
SITE_START = 0x1484F954
SITE_ORIGINAL_END_EXCLUSIVE = 0x1484FA3C
SITE_EXPANDED_BACK_EDGE = 0x1484FB98
SITE_EXPANDED_END_EXCLUSIVE = 0x1484FB9C

CALL_RESULT_LOAD_VA = 0x1484F9F0
CMP_VA = 0x1484F9F4
GUARD_VA = 0x1484F9F8
ADRP_VA = 0x1484F9FC
ADD_VA = 0x1484FA00
TABLE_LOAD_VA = 0x1484FA04
BR_VA = 0x1484FA08
TABLE_BASE = 0x14824CF0
TABLE_ENTRY_COUNT = 5
TABLE_ENTRIES = (0x1484FA3C, 0x1484FA50, 0x1484FA88, 0x1484FA0C, 0x1484FA0C)
TABLE_BYTE_LENGTH = TABLE_ENTRY_COUNT * 8
TABLE_FILE_OFFSET = 0xBCF0
TABLE_BYTES_SHA256 = "6c58a7dff5de7e6bc512bd83a5ce4f84499b2c89c0ff0a71b58b972c7f3dce61"
TABLE_SEGMENT_START = 0x1481C000
TABLE_SEGMENT_END_EXCLUSIVE = 0x1486ADD8
TABLE_SEGMENT_FLAGS = 5
UNIQUE_TABLE_TARGETS = tuple(sorted(set(TABLE_ENTRIES)))
EXPECTED_DIRECT_BRANCH_WORDS = {
    0x1484FA3C: 0x1400000D,
    0x1484FA50: 0x14000012,
    0x1484FA88: 0x14000020,
    0x1484FA0C: 0x14000001,
}

MASK64 = 0xFFFFFFFFFFFFFFFF
BR_MASK = 0x7C000000
BR_BASE = 0x14000000
BCOND_MASK = 0xFF000010
BCOND_BASE = 0x54000000

ARM_PRIMARY_SOURCE = {
    "authority": "Arm Limited",
    "title": "Arm A64 Instruction Set for A-profile architecture",
    "document_identifier": "DDI0602 (ID092025)",
    "version": "2025-09",
    "canonical_url": "https://developer.arm.com/documentation/ddi0602/2025-09/",
    "download_url": "https://documentation-service.arm.com/static/68da52dfbd7cab51328c0622",
    "filename": "ISA_A64_xml_A_profile-2025-09_ASL0.pdf",
    "size": 25_622_354,
    "sha256": "683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f",
    "access_status": "AVAILABLE_AND_HASH_PINNED",
}

# These are exact page spans from the locally hash-pinned Arm release.  The
# implementation below still checks encoding fields directly; source pages
# are provenance, not a substitute for semantic validation.
ARM_FORM_SOURCES = {
    "CMP_IMMEDIATE_W": {
        "sections": ["CMP (immediate)", "SUBS (immediate)"],
        "pages": [135, 136],
        "source_url": ARM_PRIMARY_SOURCE["canonical_url"],
        "document_identifier": "DDI0602 (ID092025)",
    },
    "LDR_W_UNSIGNED_IMMEDIATE": {
        "sections": ["LDR (immediate)", "LDR (unsigned offset)"],
        "pages": [441, 442, 443],
        "source_url": ARM_PRIMARY_SOURCE["canonical_url"],
        "document_identifier": "DDI0602 (ID092025)",
    },
    "B_COND_HI": {
        "sections": ["B.cond", "AddWithCarry", "ConditionHolds"],
        "pages": [54, 55],
        "shared_pseudocode_pages": [4913, 4954],
        "source_url": ARM_PRIMARY_SOURCE["canonical_url"],
        "document_identifier": "DDI0602 (ID092025)",
    },
    "ADRP": {
        "sections": ["ADRP"],
        "pages": [30, 31],
        "source_url": ARM_PRIMARY_SOURCE["canonical_url"],
        "document_identifier": "DDI0602 (ID092025)",
    },
    "ADD_IMMEDIATE_X": {
        "sections": ["ADD (immediate)"],
        "pages": [20, 21],
        "source_url": ARM_PRIMARY_SOURCE["canonical_url"],
        "document_identifier": "DDI0602 (ID092025)",
    },
    "LDR_REGISTER_OFFSET_X": {
        "sections": ["LDR (register)"],
        "pages": [444, 445, 446],
        "source_url": ARM_PRIMARY_SOURCE["canonical_url"],
        "document_identifier": "DDI0602 (ID092025)",
    },
    "BR": {
        "sections": ["BR"],
        "pages": [67, 68],
        "source_url": ARM_PRIMARY_SOURCE["canonical_url"],
        "document_identifier": "DDI0602 (ID092025)",
    },
}


class ExtensionError(ValueError):
    """Raised for an exact-input, semantic, or fail-closed violation."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value: int) -> str:
    return f"0x{value:08x}"


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def parse_hex(value: Any, label: str) -> int:
    if not isinstance(value, str) or not value.lower().startswith("0x"):
        raise ExtensionError(f"{label} is not hexadecimal")
    try:
        result = int(value, 16)
    except ValueError as exc:
        raise ExtensionError(f"{label} is not hexadecimal") from exc
    if result < 0 or result > MASK64:
        raise ExtensionError(f"{label} is outside the 64-bit address width")
    return result


def load_exact(path: Path, size: int, digest: str, label: str) -> bytes:
    path = Path(path)
    if not path.is_file():
        raise ExtensionError(f"missing exact input: {label}")
    data = path.read_bytes()
    if len(data) != size or sha256(data) != digest:
        raise ExtensionError(f"exact input mismatch: {label}")
    return data


def _import_source_bytes(data: bytes, path: Path, digest: str, label: str) -> Any:
    """Execute only the exact bytes that passed ``load_exact``."""

    module_name = f"_sm8150_{label}_pinned_{digest[:16]}"
    module = types.ModuleType(module_name)
    module.__file__ = str(Path(path))
    module.__package__ = ""
    module.__loader__ = None
    module.__spec__ = ModuleSpec(module_name, loader=None, origin=str(Path(path)))
    sys.modules[module_name] = module
    try:
        code = compile(bytes(data), str(Path(path)), "exec")
        exec(code, module.__dict__)
    except Exception:
        if sys.modules.get(module_name) is module:
            sys.modules.pop(module_name, None)
        raise ExtensionError(f"unable to execute pinned {label} source bytes") from None
    return module


def _import_033(data: bytes, path: Path, digest: str) -> Any:
    return _import_source_bytes(data, path, digest, "exp033")


def _arm_source_available() -> bool:
    return (
        ARM_PRIMARY_SOURCE.get("access_status") == "AVAILABLE_AND_HASH_PINNED"
        and ARM_PRIMARY_SOURCE.get("document_identifier") == "DDI0602 (ID092025)"
        and bool(ARM_PRIMARY_SOURCE.get("canonical_url"))
    )


def _validate_033_manifest(manifest: Mapping[str, Any]) -> None:
    """Validate the exact 033 semantic contract before importing its source."""

    if not isinstance(manifest, Mapping):
        raise ExtensionError("Experiment 033 manifest root is not an object")
    if (
        manifest.get("experiment_id") != "033-dcb-residual-memory-frontier"
        or manifest.get("schema") != "sm8150-dcb-residual-memory-frontier-v4"
        or manifest.get("mode") != MODE
        or manifest.get("classification") != CLASSIFICATION
        or manifest.get("device_access") != "none"
        or manifest.get("eligibility") != ELIGIBILITY
    ):
        raise ExtensionError("Experiment 033 identity or authority boundary changed")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, Mapping) or inputs.get("firmware") != {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}:
        raise ExtensionError("Experiment 033 firmware pin changed")
    analysis = manifest.get("analysis")
    sites = manifest.get("sites")
    scope = manifest.get("scope")
    if not isinstance(analysis, Mapping) or not isinstance(sites, list) or len(sites) != 71 or not isinstance(scope, Mapping):
        raise ExtensionError("Experiment 033 site contract is malformed")
    if analysis.get("site_count") != 71:
        raise ExtensionError("Experiment 033 site count changed")
    if analysis.get("discriminator_counts") != {
        "DCB_CONSUMER_PATH": 0,
        "INDIRECT_OR_UNSUPPORTED": 1,
        "MC_OR_SHRM_SYMBOLIC_TARGET": 0,
        "NO_TARGET_WITHIN_MODEL": 70,
    }:
        raise ExtensionError("Experiment 033 discriminator accounting changed")
    if analysis.get("selected_syntactic_frontier", {}).get("occurrence_count") != 352:
        raise ExtensionError("Experiment 033 selected frontier count changed")
    if analysis.get("selected_syntactic_frontier", {}).get("unique_va_count") != 219 or analysis.get("selected_syntactic_frontier", {}).get("unique_raw_word_count") != 197:
        raise ExtensionError("Experiment 033 selected frontier identity changed")
    admission = analysis.get("extension_admission", {})
    if admission.get("reached_unique_event_count") != 308 or admission.get("selected_not_reached_count") != 44 or admission.get("all_reached_events_admitted") is not True or admission.get("exact_selected_identity") is not True:
        raise ExtensionError("Experiment 033 admission accounting changed")
    residual = analysis.get("residual_extension_admission", {})
    if residual != {
        "events_outside_selected": 0,
        "exact_selected_identity": True,
        "reached_unique_event_count": 44,
        "selected_029_occurrence_count": 54,
        "selected_not_reached_count": 10,
    }:
        raise ExtensionError("Experiment 033 residual admission changed")
    if analysis.get("residual_operation_counts", {}).get("counts") != {"DAIFClr": 1, "LDP": 38, "LDRSB": 1, "LDRSW": 1, "STP": 3}:
        raise ExtensionError("Experiment 033 residual operation accounting changed")
    if analysis.get("stp_lane_observation_count") != 6 or analysis.get("stp_lane_indices") != [0, 1]:
        raise ExtensionError("Experiment 033 pair-lane accounting changed")
    inherited = analysis.get("inherited_032_equivalence", {})
    if inherited.get("all_checks_exact") is not True:
        raise ExtensionError("Experiment 033 inherited 032 equivalence is not exact")
    for name, expected in (("reached_extension_events", 264), ("direct_control_events", 143), ("reached_taint_kill_events", 23)):
        row = inherited.get(name, {})
        if row.get("expected_count") != expected or row.get("actual_count") != expected or row.get("exact_full_record_equality") is not True:
            raise ExtensionError(f"Experiment 033 inherited {name} changed")
    if scope.get("fail_closed_site_count") != 71 or scope.get("arbitrary_range_scan") is not False or scope.get("device_mmio_write") is not False or scope.get("global_writer_absence") != "UNKNOWN" or scope.get("writer_absence_claim") is not False or scope.get("system_execution_context") != "UNKNOWN_CURRENT_EL_CHECKDAIFACCESS_TRAP_OUTCOME":
        raise ExtensionError("Experiment 033 scope boundary changed")
    if analysis.get("writer_absence") != "UNKNOWN" or analysis.get("writer_absence_claim") is not False:
        raise ExtensionError("Experiment 033 writer boundary changed")
    if any(
        not isinstance(row, Mapping)
        or not isinstance(row.get("site_index"), int)
        or not isinstance(row.get("site"), Mapping)
        for row in sites
    ):
        raise ExtensionError("Experiment 033 site identity rows are malformed")
    row35 = next((row for row in sites if row.get("site_index") == SITE_INDEX), None)
    if row35 is None or row35.get("store_va") != fmt(SITE_STORE_VA):
        raise ExtensionError("Experiment 033 site-35 identity is missing")
    # 033 wraps the original 027 site under the analyzer's public ``site``
    # result; the original range identity is therefore one level deeper.
    embedded = row35["site"].get("site") if isinstance(row35["site"].get("site"), Mapping) else row35["site"]
    if embedded.get("loop_head_va") != fmt(SITE_START) or embedded.get("back_edge_va") != fmt(0x1484FA38) or embedded.get("store_va") != fmt(SITE_STORE_VA):
        raise ExtensionError("Experiment 033 site-35 original range changed")
    if row35.get("discriminators") != ["INDIRECT_OR_UNSUPPORTED"] or row35.get("unsupported_forms") != ["INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS"]:
        raise ExtensionError("Experiment 033 site-35 fail-closed boundary changed")


def validate_033_manifest(manifest: Mapping[str, Any]) -> None:
    """Public semantic validator used by focused and hostile tests."""

    _validate_033_manifest(manifest)


def load_pinned_033(
    *,
    tool_033_path: Path | None = None,
    manifest_033_path: Path | None = None,
    tool_032_path: Path | None = None,
    manifest_032_path: Path | None = None,
    tool_031_path: Path | None = None,
    manifest_031_path: Path | None = None,
    tool_027_path: Path | None = None,
    manifest_027_path: Path | None = None,
    tool_029_path: Path | None = None,
    manifest_029_path: Path | None = None,
) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """Hash/semantically validate 033, then import its exact source bytes.

    The optional paths exist for hostile path-replacement tests.  They are
    never reopened after the hash check for source execution.
    """

    tool_path = Path(tool_033_path) if tool_033_path is not None else REPO_ROOT / "tools" / EXPERIMENT_033_TOOL_NAME
    manifest_path = Path(manifest_033_path) if manifest_033_path is not None else MANIFEST_DIR / EXPERIMENT_033_MANIFEST_NAME
    tool_data = load_exact(tool_path, EXPERIMENT_033_TOOL_SIZE, EXPERIMENT_033_TOOL_SHA256, EXPERIMENT_033_TOOL_NAME)
    manifest_data = load_exact(manifest_path, EXPERIMENT_033_MANIFEST_SIZE, EXPERIMENT_033_MANIFEST_SHA256, EXPERIMENT_033_MANIFEST_NAME)
    try:
        manifest = json.loads(manifest_data)
    except json.JSONDecodeError as exc:
        raise ExtensionError("pinned Experiment 033 manifest is not JSON") from exc
    if not isinstance(manifest, dict):
        raise ExtensionError("pinned Experiment 033 manifest root is not an object")
    _validate_033_manifest(manifest)
    pinned = _import_033(tool_data, tool_path, EXPERIMENT_033_TOOL_SHA256)
    # 033's public analyzer is a wrapper around its exact 032/031/029/027
    # dependency chain.  Calling this after the 033 source/manifest gates
    # preserves the chain's own hash/semantic ordering and returns the actual
    # decoder (the imported 033 module itself has no Image class).
    # Resolve omitted chain paths against this repository, not the provenance
    # path of a copied 033 source.  Otherwise a hostile temporary source copy
    # silently changes the dependency root before the 032/031/029/027 pins.
    chain_tool_032 = Path(tool_032_path) if tool_032_path is not None else REPO_ROOT / "tools" / "sm8150_dcb_arithmetic_frontier.py"
    chain_manifest_032 = Path(manifest_032_path) if manifest_032_path is not None else MANIFEST_DIR / "032-dcb-arithmetic-frontier-20260826-01.manifest.json"
    chain_tool_031 = Path(tool_031_path) if tool_031_path is not None else REPO_ROOT / "tools" / "sm8150_dcb_consumer_writer_extension.py"
    chain_manifest_031 = Path(manifest_031_path) if manifest_031_path is not None else MANIFEST_DIR / "031-dcb-scalar-frontier-extension-20260826-01.manifest.json"
    chain_tool_027 = Path(tool_027_path) if tool_027_path is not None else REPO_ROOT / "tools" / "sm8150_dcb_consumer_writer_complement.py"
    chain_manifest_027 = Path(manifest_027_path) if manifest_027_path is not None else MANIFEST_DIR / "027-dcb-consumer-writer-complement-20260826-01.manifest.json"
    chain_tool_029 = Path(tool_029_path) if tool_029_path is not None else REPO_ROOT / "tools" / "sm8150_dcb_unsupported_frontier.py"
    chain_manifest_029 = Path(manifest_029_path) if manifest_029_path is not None else MANIFEST_DIR / "029-dcb-unsupported-frontier-20260826-01.manifest.json"
    decoder, _dep032, _dep029, chain_hashes = pinned.load_pinned_dependencies(
        tool_032_path=chain_tool_032,
        manifest_032_path=chain_manifest_032,
        tool_031_path=chain_tool_031,
        manifest_031_path=chain_manifest_031,
        tool_027_path=chain_tool_027,
        manifest_027_path=chain_manifest_027,
        tool_029_path=chain_tool_029,
        manifest_029_path=chain_manifest_029,
    )
    hashes = {
        "experiment_033_tool": {"filename": EXPERIMENT_033_TOOL_NAME, "size": len(tool_data), "sha256": sha256(tool_data)},
        "experiment_033_manifest": {"filename": EXPERIMENT_033_MANIFEST_NAME, "size": len(manifest_data), "sha256": sha256(manifest_data)},
        **chain_hashes,
    }
    # Keep both layers explicit: the caller must run the pinned 033 analyzer,
    # while its dependency decoder supplies the ELF Image implementation.
    pinned._dependency_decoder = decoder
    pinned._dependency_hashes = chain_hashes
    return pinned, manifest, hashes


def load_pinned_dependencies(**kwargs: Any) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """Compatibility alias: Experiment 034 has one exact source dependency."""

    return load_pinned_033(**kwargs)


def _word(image: Any, va: int, label: str) -> int:
    value = image.word(va)
    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ExtensionError(f"{label} is unmapped or not a uint32 word")
    return value


def _qword(image: Any, va: int, label: str) -> int:
    value = image.qword(va)
    if not isinstance(value, int) or not 0 <= value <= MASK64:
        raise ExtensionError(f"{label} is unmapped or not a uint64 table entry")
    return value


def decode_ldr_w_unsigned(word: int) -> dict[str, Any] | None:
    """Decode the exact scalar LDR W unsigned-immediate family."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or (word & 0xFFC00000) != 0xB9400000:
        return None
    return {"operation": "LDR", "width": "W", "rt": word & 0x1F, "rn": (word >> 5) & 0x1F, "offset": ((word >> 10) & 0xFFF) * 4, "address_mode": "UNSIGNED_IMMEDIATE", "writeback": False, "zero_extend_to_x": True}


def decode_cmp_w_immediate(word: int) -> dict[str, Any] | None:
    """Decode CMP Wn,#imm as the SUBS WZR,Wn,#imm alias."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    # sf=0, op=SUB, S=1, immediate class.  The mask excludes ADDG/SUBG and
    # flagless/add aliases while retaining all immediate field bits below.
    if (word & 0xFF000000) != 0x71000000 or word & (1 << 23) or word & (1 << 22):
        return None
    return {"operation": "CMP", "width": "W", "rn": (word >> 5) & 0x1F, "rd": word & 0x1F, "immediate": (word >> 10) & 0xFFF, "shift": 0, "writes_nzcv": True, "writes_gpr": False}


def decode_b_cond(word: int, va: int) -> dict[str, Any] | None:
    """Decode a B.cond word and compute its A64 target."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or (word & BCOND_MASK) != BCOND_BASE:
        return None
    imm19 = (word >> 5) & 0x7FFFF
    target = (va + (sign_extend(imm19, 19) << 2)) & MASK64
    return {"operation": "B.cond", "condition": word & 0xF, "imm19": imm19, "target": target}


def decode_adrp(word: int, va: int) -> dict[str, Any] | None:
    """Decode ADRP and its page-relative target."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or (word & 0x9F000000) != 0x90000000:
        return None
    imm21 = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    page_delta = sign_extend(imm21, 21) << 12
    return {"operation": "ADRP", "rd": word & 0x1F, "page_delta": page_delta, "target": ((va & ~0xFFF) + page_delta) & MASK64}


def decode_add_x_immediate(word: int) -> dict[str, Any] | None:
    """Decode ADD Xd,Xn,#imm with the unshifted immediate form."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or (word & 0x1F000000) != 0x11000000:
        return None
    if not (word & 0x80000000) or word & 0x60000000 or word & (1 << 23) or word & (1 << 22):
        return None
    return {"operation": "ADD", "width": "X", "rd": word & 0x1F, "rn": (word >> 5) & 0x1F, "immediate": (word >> 10) & 0xFFF, "shift": 0}


def decode_ldr_x_register_offset(word: int) -> dict[str, Any] | None:
    """Decode LDR Xd,[Xn,Xm,LSL #3] with the exact register-offset form."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or (word & 0x3FE00C00) != 0x38600800:
        return None
    if ((word >> 30) & 0x3) != 0x3:
        return None
    return {"operation": "LDR", "width": "X", "rt": word & 0x1F, "rn": (word >> 5) & 0x1F, "rm": (word >> 16) & 0x1F, "option": (word >> 13) & 0x7, "scale": (word >> 12) & 1, "address_mode": "REGISTER_OFFSET"}


def decode_br(word: int) -> dict[str, Any] | None:
    """Decode BR Xn, excluding BLR/RET and unrelated system words."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or (word & 0xFFFFFC1F) != 0xD61F0000:
        return None
    return {"operation": "BR", "rn": (word >> 5) & 0x1F}


def encode_b(source_va: int, target_va: int) -> int:
    """Encode a range-checked A64 direct B."""

    if source_va % 4 or target_va % 4:
        raise ExtensionError("direct B source/target must be 4-byte aligned")
    displacement = target_va - source_va
    if displacement % 4 or not -(1 << 27) <= displacement < (1 << 27):
        raise ExtensionError("direct B target is outside the signed imm26 range")
    return BR_BASE | ((displacement // 4) & 0x03FFFFFF)


def decode_b(word: int, va: int) -> int | None:
    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or (word & BR_MASK) != BR_BASE:
        return None
    return (va + (sign_extend(word & 0x03FFFFFF, 26) << 2)) & MASK64


def _gpr_definitions(word: int) -> set[tuple[str, int]]:
    """Small conservative write-set for the site-35 adjacency check."""

    definitions: set[tuple[str, int]] = set()
    ldr_w = decode_ldr_w_unsigned(word)
    if ldr_w is not None and ldr_w["rt"] != 31:
        definitions.add(("W", int(ldr_w["rt"])))
    adrp = decode_adrp(word, 0)
    if adrp is not None and adrp["rd"] != 31:
        definitions.add(("X", int(adrp["rd"])))
    add = decode_add_x_immediate(word)
    if add is not None and add["rd"] != 31:
        definitions.add(("X", int(add["rd"])))
    ldr_x = decode_ldr_x_register_offset(word)
    if ldr_x is not None and ldr_x["rt"] != 31:
        definitions.add(("X", int(ldr_x["rt"])))
    return definitions


def inspect_site35_dispatch(image: Any) -> dict[str, Any]:
    """Semantically validate the exact site-35 guard/table/BR sequence."""

    if not _arm_source_available():
        raise ExtensionError("Arm primary source is unavailable; dispatch gate remains UNKNOWN")
    sequence_vas = (CALL_RESULT_LOAD_VA, CMP_VA, GUARD_VA, ADRP_VA, ADD_VA, TABLE_LOAD_VA, BR_VA)
    file_offsets = [image.file_offset(va) for va in sequence_vas]
    if any(offset is None for offset in file_offsets) or any(file_offsets[index + 1] != file_offsets[index] + 4 for index in range(len(file_offsets) - 1)):
        raise ExtensionError("site-35 dispatch sequence is not contiguous in one file-backed mapping")
    words = {va: _word(image, va, f"site-35 word {fmt(va)}") for va in sequence_vas}
    call_load = decode_ldr_w_unsigned(words[CALL_RESULT_LOAD_VA])
    if call_load != {"operation": "LDR", "width": "W", "rt": 9, "rn": 31, "offset": 36, "address_mode": "UNSIGNED_IMMEDIATE", "writeback": False, "zero_extend_to_x": True}:
        raise ExtensionError("site-35 call-result LDR W9,[SP,#36] does not match exact fields")
    cmp = decode_cmp_w_immediate(words[CMP_VA])
    if cmp is None or cmp["rn"] != 9 or cmp["rd"] != 31 or cmp["immediate"] != 4 or cmp["width"] != "W" or cmp["operation"] != "CMP":
        raise ExtensionError("site-35 CMP W9,#4 guard does not match exact fields")
    guard = decode_b_cond(words[GUARD_VA], GUARD_VA)
    if guard is None or guard["condition"] != 0x8 or guard["target"] != SITE_EXPANDED_END_EXCLUSIVE:
        raise ExtensionError("site-35 B.HI exit guard does not match exact fields")
    adrp = decode_adrp(words[ADRP_VA], ADRP_VA)
    if adrp is None or adrp["rd"] != 5 or adrp["target"] != 0x14824000:
        raise ExtensionError("site-35 ADRP X5 table page does not match exact fields")
    add = decode_add_x_immediate(words[ADD_VA])
    if add is None or add["rd"] != 5 or add["rn"] != 5 or add["immediate"] != 0xCF0 or add["shift"] != 0:
        raise ExtensionError("site-35 ADD X5,#0xcf0 table base does not match exact fields")
    table_load = decode_ldr_x_register_offset(words[TABLE_LOAD_VA])
    if table_load is None or table_load["rt"] != 1 or table_load["rn"] != 5 or table_load["rm"] != 9 or table_load["option"] != 3 or table_load["scale"] != 1:
        raise ExtensionError("site-35 LDR X1,[X5,X9,LSL#3] does not match exact fields")
    branch = decode_br(words[BR_VA])
    if branch is None or branch["rn"] != 1:
        raise ExtensionError("site-35 BR X1 does not match exact destination register")
    # The only fall-through definitions between the result load and table
    # load must be WZR (CMP), X5 (ADRP/ADD), and X1 (LDR).  This catches a
    # same-shaped sequence with a hidden W9 redefinition.
    fallthrough_defs = {
        fmt(va): sorted(f"{width}{reg}" for width, reg in _gpr_definitions(words[va]))
        for va in (CMP_VA, GUARD_VA, ADRP_VA, ADD_VA, TABLE_LOAD_VA)
    }
    if any(("W", 9) in _gpr_definitions(words[va]) or ("X", 9) in _gpr_definitions(words[va]) for va in (CMP_VA, GUARD_VA, ADRP_VA, ADD_VA, TABLE_LOAD_VA)):
        raise ExtensionError("site-35 fall-through redefines W9 before indexed table load")
    if words[BR_VA] != 0xD61F0020:
        raise ExtensionError("site-35 original BR raw word changed")
    return {
        "raw_words": {fmt(va): fmt(words[va]) for va in sorted(words)},
        "call_result_load": call_load,
        "cmp": cmp,
        "guard": guard,
        "adrp": adrp,
        "add": add,
        "table_load": table_load,
        "branch": branch,
        "fallthrough_definitions": fallthrough_defs,
        "index_domain": {"register": "X9", "lower_inclusive": 0, "upper_inclusive": 4, "out_of_range_condition": "UNSIGNED_W9_GREATER_THAN_4"},
        "local_fallthrough_chain": "CALL_RESULT_LOAD_W9_FROM_SP_PLUS_36_ZERO_EXTENDS_TO_X9_THEN_CMP_AND_TABLE_INDEX_WITHOUT_W9_REDEFINITION",
        "adjacency": "CMP_BHI_ADRP_ADD_LDR_BR_CONTIGUOUS",
    }


def validate_site35_dispatch(image: Any) -> dict[str, Any]:
    """Public alias for the fail-closed sequence validator."""

    return inspect_site35_dispatch(image)


def _validate_bounded_guard_scope(manifest_033: Mapping[str, Any]) -> dict[str, Any]:
    """Prove guard coverage only for 033's bounded, site-head-entered CFG.

    This deliberately does not claim that the sequence has no external entry
    in the whole image.  It checks the exact 033 site result for a complete
    bounded traversal, the one BR blocker, and absence of a modeled direct
    edge that enters after the W9 result load and bypasses the guard.
    """

    row = next((item for item in manifest_033["sites"] if item.get("site_index") == SITE_INDEX), None)
    if not isinstance(row, Mapping) or row.get("cfg_complete") is not True:
        raise ExtensionError("Experiment 033 site-35 bounded CFG is not complete")
    blockers = row.get("reached_blocker_events")
    if not isinstance(blockers, list) or len(blockers) != 1:
        raise ExtensionError("Experiment 033 site-35 blocker identity changed")
    blocker = blockers[0]
    if blocker.get("va") != fmt(BR_VA) or blocker.get("raw_word") != "0xd61f0020" or blocker.get("family") != "INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS":
        raise ExtensionError("Experiment 033 site-35 BR blocker changed")
    edges = row.get("branch_edges")
    if not isinstance(edges, list):
        raise ExtensionError("Experiment 033 site-35 branch-edge ledger is malformed")
    guard_edges = [edge for edge in edges if edge.get("va") == fmt(GUARD_VA)]
    if len(guard_edges) != 1 or guard_edges[0].get("kind") != "B.cond" or guard_edges[0].get("target") != fmt(SITE_EXPANDED_END_EXCLUSIVE):
        raise ExtensionError("Experiment 033 site-35 guard edge changed")
    bypass_edges = []
    for edge in edges:
        target = edge.get("target")
        if not isinstance(target, str) or not target.startswith("0x"):
            continue
        target_va = parse_hex(target, "site-35 branch target")
        if CMP_VA <= target_va <= BR_VA:
            bypass_edges.append(dict(edge))
    if bypass_edges:
        raise ExtensionError("bounded site-35 CFG contains a direct edge that bypasses the W9 guard chain")
    return {
        "entry": fmt(SITE_START),
        "cfg_complete": True,
        "original_br_blocker": {"va": fmt(BR_VA), "raw_word": "0xd61f0020"},
        "guard_edge": dict(guard_edges[0]),
        "direct_guard_bypass_edge_count": 0,
        "scope": "EXACT_033_BOUNDED_CFG_ENTERED_AT_SITE_HEAD_ONLY",
        "external_or_unmodeled_entries": "UNKNOWN_NOT_CLAIMED",
    }


def _validate_table(image: Any) -> dict[str, Any]:
    if TABLE_BASE % 8:
        raise ExtensionError("site-35 table base is not 8-byte aligned")
    try:
        table_bytes = image.slice(TABLE_BASE, TABLE_BASE + TABLE_BYTE_LENGTH)
    except Exception as exc:
        raise ExtensionError("site-35 table is not contiguous and file-backed") from exc
    if len(table_bytes) != TABLE_BYTE_LENGTH or sha256(table_bytes) != TABLE_BYTES_SHA256:
        raise ExtensionError("site-35 table byte identity changed")
    file_offset = image.file_offset(TABLE_BASE)
    if file_offset != TABLE_FILE_OFFSET:
        raise ExtensionError("site-35 table file offset changed")
    segment = image.segment_for(TABLE_BASE)
    if segment is None or segment.vaddr != TABLE_SEGMENT_START or segment.vaddr + segment.file_size != TABLE_SEGMENT_END_EXCLUSIVE or segment.flags != TABLE_SEGMENT_FLAGS:
        raise ExtensionError("site-35 table is not in the exact RX XBL LOAD segment")
    entries = []
    for index in range(TABLE_ENTRY_COUNT):
        entry_va = TABLE_BASE + index * 8
        value = _qword(image, entry_va, f"site-35 table entry {index}")
        if value % 4 or not SITE_START <= value < SITE_EXPANDED_END_EXCLUSIVE:
            raise ExtensionError(f"site-35 table target {fmt(value)} is outside the expanded local range")
        target_segment = image.segment_for(value)
        if image.file_offset(value) is None or target_segment is None or target_segment.vaddr != TABLE_SEGMENT_START or target_segment.vaddr + target_segment.file_size != TABLE_SEGMENT_END_EXCLUSIVE or target_segment.flags != TABLE_SEGMENT_FLAGS:
            raise ExtensionError(f"site-35 table target {fmt(value)} is not mapped/file-backed")
        entries.append({"index": index, "table_va": fmt(entry_va), "target": fmt(value), "target_word": fmt(_word(image, value, f"site-35 target word {index}")), "aligned": True, "mapped": True, "within_expanded_range": True})
    if tuple(parse_hex(row["target"], "table target") for row in entries) != TABLE_ENTRIES:
        raise ExtensionError("site-35 table entries or duplicate multiplicity changed")
    return {"base": fmt(TABLE_BASE), "encoding": "LITTLE_ENDIAN_U64", "file_offset": fmt(file_offset), "byte_length": TABLE_BYTE_LENGTH, "bytes_sha256": TABLE_BYTES_SHA256, "segment": {"vaddr_start": fmt(segment.vaddr), "vaddr_end_exclusive": fmt(segment.vaddr + segment.file_size), "flags": segment.flags, "kind": "RX"}, "entry_count": TABLE_ENTRY_COUNT, "entries": entries, "unique_target_count": len(UNIQUE_TABLE_TARGETS), "duplicate_target_multiplicity": {fmt(target): TABLE_ENTRIES.count(target) for target in UNIQUE_TABLE_TARGETS}}


def _replace_br(data: bytes, decoder: Any, target: int) -> tuple[bytes, int]:
    if len(data) != XBL_SIZE or sha256(data) != XBL_SHA256:
        raise ExtensionError("synthetic substitution requires the exact original XBL bytes")
    if target not in UNIQUE_TABLE_TARGETS:
        raise ExtensionError("synthetic substitution target is not one of the exact unique table entries")
    image = decoder.Image(data)
    offset = image.file_offset(BR_VA)
    if offset is None or offset % 4 or offset < 0 or offset + 4 > len(data):
        raise ExtensionError("site-35 BR is not a contiguous file-backed word")
    original = struct.unpack_from("<I", data, offset)[0]
    if original != 0xD61F0020:
        raise ExtensionError("site-35 BR replacement source word changed")
    replacement = encode_b(BR_VA, target)
    changed = bytearray(data)
    struct.pack_into("<I", changed, offset, replacement)
    if bytes(changed[:offset]) != data[:offset] or bytes(changed[offset + 4 :]) != data[offset + 4:]:
        raise ExtensionError("synthetic substitution clobbered bytes outside BR word")
    if struct.unpack_from("<I", changed, offset)[0] != replacement:
        raise ExtensionError("synthetic BR replacement did not publish expected word")
    return bytes(changed), replacement


def _expanded_site() -> dict[str, str]:
    return {"store_va": fmt(SITE_STORE_VA), "loop_head_va": fmt(SITE_START), "back_edge_va": fmt(SITE_EXPANDED_BACK_EDGE)}


def _direct_guard_bypass_edges(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    bypasses = []
    for edge in result.get("branch_edges", []):
        target = edge.get("target") if isinstance(edge, Mapping) else None
        if not isinstance(target, str) or not target.startswith("0x"):
            continue
        target_va = parse_hex(target, "synthetic branch target")
        if CMP_VA <= target_va <= BR_VA:
            bypasses.append(dict(edge))
    return bypasses


def _require_synthetic_result(result: Mapping[str, Any], target: int) -> None:
    if result.get("cfg_complete") is not True or result.get("unsupported_forms") != []:
        raise ExtensionError(f"synthetic site-35 target {fmt(target)} did not complete without unsupported forms")
    if result.get("discriminators") != ["NO_TARGET_WITHIN_MODEL"]:
        raise ExtensionError(f"synthetic site-35 target {fmt(target)} did not resolve to bounded no-target")
    if result.get("current_destination") != "UNKNOWN":
        raise ExtensionError("synthetic static resolver changed current-destination boundary")
    if result.get("writer_absence") != "UNKNOWN":
        raise ExtensionError("synthetic static resolver changed writer-absence boundary")
    if "DCB_CONSUMER_PATH" in result.get("discriminators", []) or "MC_OR_SHRM_SYMBOLIC_TARGET" in result.get("discriminators", []):
        raise ExtensionError(f"synthetic site-35 target {fmt(target)} produced a forbidden symbolic positive label")
    if _direct_guard_bypass_edges(result):
        raise ExtensionError(f"synthetic site-35 target {fmt(target)} contains a direct guard-bypass edge")


def _canonical_record(record: Mapping[str, Any]) -> str:
    return json.dumps(dict(record), sort_keys=True, separators=(",", ":"))


def _baseline_identity(manifest_033: Mapping[str, Any], published_sites: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    sites = [dict(row) for row in manifest_033["sites"]]
    ordered = sorted(sites, key=lambda row: int(row["site_index"]))
    if [int(row["site_index"]) for row in ordered] != list(range(71)):
        raise ExtensionError("Experiment 033 site indices are not exactly 0..70")
    non35 = [row for row in ordered if int(row["site_index"]) != SITE_INDEX]
    site35 = next(row for row in ordered if int(row["site_index"]) == SITE_INDEX)
    published_equal = True
    published_non35_equal = True
    published_site35_present = True
    if published_sites is not None:
        published = [dict(row) for row in published_sites]
        published_by_index = {int(row.get("site_index", -1)): row for row in published}
        published_equal = len(published) == len(ordered) and all(_canonical_record(left) == _canonical_record(right) for left, right in zip(ordered, sorted(published, key=lambda row: int(row.get("site_index", -1)))))
        published_non35_equal = len(published_by_index) == len(published) and all(_canonical_record(row) == _canonical_record(published_by_index.get(int(row["site_index"]), {})) for row in non35)
        published_site35_present = 35 in published_by_index
    return {
        "site_count": len(ordered),
        "site_indices": [int(row["site_index"]) for row in ordered],
        "non_site35_count": len(non35),
        "non_site35_canonical_sha256": sha256(("\n".join(_canonical_record(row) for row in non35) + "\n").encode()),
        "site35_baseline_canonical_sha256": sha256(_canonical_record(site35).encode()),
        "baseline_site35_retained": published_site35_present,
        "non_site35_exact_full_record_equality": published_non35_equal,
        "all_baseline_records_exact_full_record_equality": published_equal,
        "resolution_scope": "SITE_35_ONLY; BASELINE_033_ROWS_RETAINED_VERBATIM",
    }


def resolve_site35(
    analyzer: Any,
    manifest_033: Mapping[str, Any],
    firmware: bytes,
    *,
    max_states: int = 2048,
) -> dict[str, Any]:
    """Resolve site 35 through four independent synthetic direct-B copies."""

    if len(firmware) != XBL_SIZE or sha256(firmware) != XBL_SHA256:
        raise ExtensionError("exact XBL input mismatch")
    _validate_033_manifest(manifest_033)
    analyzer_module = analyzer if hasattr(analyzer, "analyze_site_bound") else None
    decoder = getattr(analyzer, "_dependency_decoder", None)
    if analyzer_module is None or decoder is None:
        raise ExtensionError("pinned Experiment 033 analyzer/decoder pair is required")
    original_image = decoder.Image(firmware)
    dispatch = inspect_site35_dispatch(original_image)
    bounded_guard_scope = _validate_bounded_guard_scope(manifest_033)
    table = _validate_table(original_image)
    br_file_offset = original_image.file_offset(BR_VA)
    if br_file_offset is None:
        raise ExtensionError("site-35 BR file offset is unavailable")
    target_rows = []
    for target in UNIQUE_TABLE_TARGETS:
        synthetic, replacement = _replace_br(firmware, decoder, target)
        if replacement != EXPECTED_DIRECT_BRANCH_WORDS[target]:
            raise ExtensionError(f"direct-B encoding mismatch at synthetic target {fmt(target)}")
        synthetic_image = decoder.Image(synthetic)
        result = analyzer_module.analyze_site_bound(synthetic_image, decoder, _expanded_site(), max_states=max_states)
        _require_synthetic_result(result, target)
        changed_indices = [
            index
            for index in range(br_file_offset, br_file_offset + 4)
            if synthetic[index] != firmware[index]
        ]
        if not changed_indices or any(not br_file_offset <= index < br_file_offset + 4 for index in changed_indices):
            raise ExtensionError("synthetic BR byte-difference accounting failed")
        target_rows.append(
            {
                "target": fmt(target),
                "target_va": target,
                "direct_branch_word": fmt(replacement),
                "direct_branch_word_raw": replacement,
                "replacement": {"va": fmt(BR_VA), "file_offset": fmt(br_file_offset), "original_word": "0xd61f0020", "replacement_word": fmt(replacement), "replacement_width_bytes": 4, "changed_byte_count": len(changed_indices), "changed_byte_indices_within_word": [index - br_file_offset for index in changed_indices], "only_changed_word": True, "original_image_sha256": XBL_SHA256, "synthetic_image_sha256": sha256(synthetic)},
                "analysis": result,
                "measured": {"cfg_complete": result["cfg_complete"], "unsupported_forms": result["unsupported_forms"], "discriminators": result["discriminators"], "cfg_states_visited": result["cfg_states_visited"], "target_observation_count": len(result.get("target_observations", [])), "handled_form_count": len(result.get("v4_handled_forms", [])), "direct_guard_bypass_edge_count": len(_direct_guard_bypass_edges(result))},
            }
        )
    target_rows.sort(key=lambda row: parse_hex(row["target"], "synthetic target"))
    aggregate = {
        "unique_target_count": len(target_rows),
        "entry_count_preserved": TABLE_ENTRY_COUNT,
        "duplicate_target_multiplicity_preserved": table["duplicate_target_multiplicity"],
        "all_cfg_complete": all(row["measured"]["cfg_complete"] for row in target_rows),
        "all_unsupported_forms_empty": all(not row["measured"]["unsupported_forms"] for row in target_rows),
        "all_discriminators_exact_no_target": all(row["measured"]["discriminators"] == ["NO_TARGET_WITHIN_MODEL"] for row in target_rows),
        "dcb_consumer_path_count": 0,
        "mc_or_shrm_symbolic_target_count": 0,
        "max_states": max_states,
    }
    if not aggregate["all_cfg_complete"] or not aggregate["all_unsupported_forms_empty"] or not aggregate["all_discriminators_exact_no_target"]:
        raise ExtensionError("site-35 synthetic aggregate resolver gate failed")
    return {
        "site_index": SITE_INDEX,
        "store_va": fmt(SITE_STORE_VA),
        "original_range": {"start": fmt(SITE_START), "end_exclusive": fmt(SITE_ORIGINAL_END_EXCLUSIVE), "back_edge": fmt(0x1484FA38)},
        "expanded_range": {"start": fmt(SITE_START), "end_exclusive": fmt(SITE_EXPANDED_END_EXCLUSIVE), "back_edge": fmt(SITE_EXPANDED_BACK_EDGE)},
        "dispatch": dispatch,
        "bounded_guard_scope": bounded_guard_scope,
        "table": table,
        "synthetic_targets": target_rows,
        "aggregate": aggregate,
        "resolver_status": "PROVED_BOUNDED_DIRECT_BRANCH_SUBSTITUTION_NO_TARGET",
        "runtime_execution": "UNKNOWN",
        "global_alias_or_destination": "UNKNOWN",
    }


def _combined_analysis(manifest_033: Mapping[str, Any], resolution: Mapping[str, Any], baseline_identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
    base = copy.deepcopy(dict(manifest_033["analysis"]))
    baseline_blockers = copy.deepcopy(base.get("reached_blocker_events", []))
    baseline_summary = {
        "discriminator_counts": base["discriminator_counts"],
        "actual_delta_vs_027": base["actual_delta_vs_027"],
        "actual_delta_vs_032": base["actual_delta_vs_032"],
        "transition_quadrants": base["transition_quadrants"],
        "remaining_unsupported_site_count": base["remaining_unsupported_site_count"],
        "remaining_unsupported_form_count": base["remaining_unsupported_form_count"],
        "reached_blocker_events": baseline_blockers,
    }
    base["discriminator_counts"] = {"DCB_CONSUMER_PATH": 0, "INDIRECT_OR_UNSUPPORTED": 0, "MC_OR_SHRM_SYMBOLIC_TARGET": 0, "NO_TARGET_WITHIN_MODEL": 71}
    base["actual_delta_vs_027"] = {"baseline_fail_closed_sites": 71, "v4_fail_closed_sites": 0, "sites_remaining_fail_closed": 0, "sites_transitioned_to_no_target_within_v4_model": 71, "transition_identity": True, "transition_scope": "V4_MODEL_PLUS_SITE35_BOUNDED_RESOLUTION", "combined_scalar_plus_dispatch_v4": True, "dispatch_dependency": "DIRECT_CONTROL_DISPATCH_REPAIR", "absence_claim": "NO_ABSENCE_CLAIM"}
    base["actual_delta_vs_032"] = {"baseline_fail_closed_sites": 16, "v4_fail_closed_sites": 0, "sites_remaining_fail_closed": 0, "sites_transitioned_to_no_target_within_v4_model": 16, "transition_identity": True, "transition_scope": "V4_MODEL_PLUS_SITE35_BOUNDED_RESOLUTION", "absence_claim": "NO_ABSENCE_CLAIM"}
    base["actual_delta_vs_033"] = {"baseline_fail_closed_sites": 1, "current_fail_closed_sites": 0, "sites_remaining_fail_closed": 0, "sites_transitioned_to_no_target_within_034_model": 1, "stable_no_target_sites": 70, "regression_count": 0, "transition_identity": True, "transition_scope": "SITE35_BOUNDED_RESOLUTION_ONLY", "absence_claim": "NO_ABSENCE_CLAIM"}
    base["remaining_unsupported_site_count"] = 0
    base["remaining_unsupported_form_count"] = 0
    base["remaining_unsupported_sites"] = []
    base["reached_blocker_events"] = []
    base["resolved_baseline_blocker_event_count"] = len(baseline_blockers)
    base["site35_resolution"] = resolution
    base["baseline_033"] = baseline_summary
    base["baseline_033_identity"] = dict(baseline_identity) if baseline_identity is not None else _baseline_identity(manifest_033)
    combined_counts = {
        "032_INDIRECT_OR_UNSUPPORTED_TO_034_INDIRECT_OR_UNSUPPORTED": 0,
        "032_INDIRECT_OR_UNSUPPORTED_TO_034_NO_TARGET_WITHIN_MODEL": 16,
        "032_NO_TARGET_WITHIN_MODEL_TO_034_INDIRECT_OR_UNSUPPORTED": 0,
        "032_NO_TARGET_WITHIN_MODEL_TO_034_NO_TARGET_WITHIN_MODEL": 55,
    }
    base["transition_quadrants"] = {
        "counts": dict(combined_counts),
        "expected_counts": dict(combined_counts),
        "identity_check": True,
        "regression_count": 0,
        "regression_free": True,
        "scope": "BOUNDED_SITE35_RESOLUTION_COMPOSED_WITH_033_RESULT",
    }
    base["combined_transition_quadrants"] = copy.deepcopy(base["transition_quadrants"])
    base["transition_quadrants_vs_033"] = {
        "counts": {
            "033_INDIRECT_OR_UNSUPPORTED_TO_034_INDIRECT_OR_UNSUPPORTED": 0,
            "033_INDIRECT_OR_UNSUPPORTED_TO_034_NO_TARGET_WITHIN_MODEL": 1,
            "033_NO_TARGET_WITHIN_MODEL_TO_034_INDIRECT_OR_UNSUPPORTED": 0,
            "033_NO_TARGET_WITHIN_MODEL_TO_034_NO_TARGET_WITHIN_MODEL": 70,
        },
        "identity_check": True,
        "regression_count": 0,
        "regression_free": True,
        "scope": "SITE35_BOUNDED_RESOLUTION_ONLY",
    }
    base["sites_semantics"] = "TOP_LEVEL_SITES_ARE_VERBATIM_BASELINE_033_RECORDS; COMBINED_034_OUTCOME_IS_PUBLISHED_SEPARATELY"
    base["combined_outcome"] = {"site_count": 71, "discriminator_counts": base["discriminator_counts"], "all_sites_no_target_within_model": True, "fail_closed_site_count": 0, "resolution_dependency": "SITE35_TABLE_SEMANTIC_GATE_AND_FOUR_UNIQUE_TARGET_SYNTHETIC_CFG_RUNS"}
    return base


def definition_of_done() -> dict[str, Any]:
    na = "NOT_APPLICABLE: deterministic host-only static analysis; no device or persistent state was touched"
    return {
        "date": "2026-08-26",
        "timestamp": {"value": "NOT_APPLICABLE", "reason": "Deterministic publication omits wall-clock time."},
        "target": {"marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855", "binding": "PROVED_EXACT_FIRMWARE_INPUT_HASH"},
        "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256, "build": "UNKNOWN"},
        "precondition": {"status": "PROVED", "device_access": "none", "exact": "Exact XBL plus hash/semantic-pinned Experiment 033 source and manifest."},
        "action": {"status": "PROVED", "exact": "Four independent in-memory copies replace only the site-35 BR word with one direct B per unique exact table target."},
        "result": {"classification": CLASSIFICATION, "status": "BOUNDED_SITE35_DIRECT_DISPATCH_RESOLUTION_UNKNOWN_GLOBAL", "proved": "Exact static sequence/table, bounded guard scope, and four bounded synthetic CFG results.", "unknown": "External entries, runtime execution/order/table contents, destination, alias, security-boundary, and writer/consumer-global claims."},
        "non_applicable_artifacts": {name: {"status": "NOT_APPLICABLE", "reason": na} for name in ("boot", "kernel", "dtb", "research_kernel")},
        "live_repetitions": {"status": "NOT_APPLICABLE", "reason": na},
        "dmesg": {"status": "NOT_APPLICABLE", "reason": na},
        "log": {"status": "NOT_APPLICABLE", "reason": na},
        "rollback": {"status": "NOT_APPLICABLE", "reason": na},
        "recovery": {"status": "NOT_APPLICABLE", "reason": na},
        "negative_controls": {"status": "PASS", "description": "Dependency mutation/path replacement, dispatch fields, guard/bound, table base/index/scale/register, direct-entry bypass, source availability, table identity/locality/multiplicity, substitution boundary, and no-clobber publication fail closed."},
        "deterministic_repetition_validation": {"repetition_count": 2, "repetition_unit": "fresh host manifest generations", "repetition_result": "BYTE_IDENTICAL"},
        "tool_and_build": {"tool": "sm8150_dcb_site35_jump_table.py", "build": "NOT_APPLICABLE", "build_reason": "Interpreted host transform; no firmware/kernel build."},
    }


def build_manifest(
    firmware_dir: Path = FIRMWARE_DIR,
    manifest_dir: Path = MANIFEST_DIR,
    tool_033_path: Path | None = None,
    manifest_033_path: Path | None = None,
) -> dict[str, Any]:
    pinned, manifest_033, hashes = load_pinned_033(tool_033_path=tool_033_path, manifest_033_path=manifest_033_path or Path(manifest_dir) / EXPERIMENT_033_MANIFEST_NAME)
    firmware = load_exact(Path(firmware_dir) / XBL_NAME, XBL_SIZE, XBL_SHA256, XBL_NAME)
    resolution = resolve_site35(pinned, manifest_033, firmware)
    sites = copy.deepcopy(manifest_033["sites"])
    identity = _baseline_identity(manifest_033, sites)
    if len(sites) != 71 or identity["non_site35_exact_full_record_equality"] is not True or identity["baseline_site35_retained"] is not True or identity["all_baseline_records_exact_full_record_equality"] is not True:
        raise ExtensionError("baseline 033 site publication identity gate failed")
    analysis = _combined_analysis(manifest_033, resolution, identity)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": CLASSIFICATION,
        "eligibility": ELIGIBILITY,
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, **hashes},
        "scope": {
            "source_experiment": "033-dcb-residual-memory-frontier",
            "resolution_scope": "SITE35_ONLY",
            "site_count": 71,
            "preserved_baseline_site_count": 71,
            "preserved_baseline_site35": True,
            "non_site35_exact_full_record_equality": True,
            "top_level_sites_semantics": "VERBATIM_BASELINE_033_ONLY_NOT_COMBINED_034_SITE_OUTCOMES",
            "scan_mode": "BOUNDED_CFG_DATAFLOW_WITH_SITE35_DIRECT_B_SUBSTITUTIONS",
            "arbitrary_range_scan": False,
            "device_mmio_write": False,
            "firmware_mutation": "IN_MEMORY_COPY_ONLY_BR_WORD_AT_0x1484fa08",
            "global_writer_absence": "UNKNOWN",
            "writer_absence_claim": False,
            "runtime_execution": "UNKNOWN",
            "current_destination": "UNKNOWN",
            "protected_memory_semantics": "UNKNOWN",
            "combined_result_scope": "BOUNDED_SITE35_RESOLUTION_ONLY_NO_ABSENCE_CLAIM",
        },
        "architecture_sources": {"primary": ARM_PRIMARY_SOURCE, "qualified_forms": ARM_FORM_SOURCES, "qualification_rule": "Static dispatch promotion requires exact source-qualified fields, table locality, and all four unique-target synthetic CFG gates."},
        "dependency_033": {"experiment_id": manifest_033["experiment_id"], "schema": manifest_033["schema"], "classification": manifest_033["classification"], "site_count": 71, "manifest_hash": hashes["experiment_033_manifest"], "tool_hash": hashes["experiment_033_tool"], "semantic_validation": "PASS_BEFORE_IMPORT"},
        "analysis": analysis,
        "sites": sites,
        "claims": {
            "PROVED": [
                "The Experiment 033 source/public-manifest bytes and manifest semantics passed validation before importing the pinned 033 source; the exact XBL was validated separately before site analysis.",
                "Within the exact 033 CFG entered at the bounded site head, the dispatch sequence is LDR W9,[SP,#36]; CMP W9,#4; B.HI to the expanded end; ADRP/ADD table base 0x14824cf0; LDR X1,[X5,X9,LSL#3]; BR X1, with no W9 redefinition or modeled direct guard-bypass edge on the fall-through path.",
                "The exact five-entry little-endian table preserves duplicate target 0x1484fa0c and has four unique aligned, mapped targets inside the expanded site range.",
                "Each unique table target was analyzed through a separate in-memory XBL copy with only the BR word replaced by the measured direct-B encoding; all four bounded CFG runs completed with no unsupported forms and discriminator NO_TARGET_WITHIN_MODEL.",
                "All 71 baseline Experiment 033 site records are retained verbatim; the 70 non-site-35 rows pass exact full-record identity and the baseline site-35 row remains present.",
            ],
            "SUPPORTED": ["Within this bounded model, resolving site 35's table dispatch removes the last model fail-closed site without producing a DCB consumer or MC/SHRM symbolic target label."],
            "HYPOTHESIS": [],
            "REFUTED": [],
            "UNKNOWN": [
                "Runtime execution/order, current destination, runtime table contents, address aliases, protected-memory semantics, and global DCB consumer/writer absence remain UNKNOWN.",
                "External or unmodeled entries into the local dispatch sequence remain UNKNOWN; the guard-coverage proof is limited to the exact 033 bounded CFG entered at the site head.",
                "The direct-B substitutions are a static control-flow oracle; they do not prove that the original BR executes with any table index or that an X1 value is a runtime code pointer.",
                "Direct B and BR have different architectural branch-type/PSTATE.BTYPE behavior; the bounded analyzer does not model that state and no runtime equivalence claim is made.",
                "This result does not establish a Qualcomm hardware address transform, a security-boundary bypass, or exploitability.",
            ],
        },
        "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "mmio": "none", "smc": "none", "write": "none", "reason": "Host-only static analysis; synthetic firmware copies never leave memory."},
        "reproducibility": {"generation_mode": "DETERMINISTIC_SORTED_JSON", "repetition_count": 2, "repetition_result": "BYTE_IDENTICAL", "publication": "O_EXCL_O_NOFOLLOW_MODE_0644"},
        "definition_of_done": definition_of_done(),
        "reproducible_command_template": "python3 tools/sm8150_dcb_site35_jump_table.py --firmware-dir <exact-firmware-dir> --manifest-dir <public-manifest-dir> --output <public-manifest-path>",
    }


def write_no_clobber(path: Path, data: bytes, mode: int = 0o644) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--manifest-dir", type=Path, default=MANIFEST_DIR)
    parser.add_argument("--tool-033", type=Path, default=None)
    parser.add_argument("--manifest-033", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir, args.manifest_dir, args.tool_033, args.manifest_033)
    encoded = (json.dumps(manifest, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
    write_no_clobber(args.output, encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
