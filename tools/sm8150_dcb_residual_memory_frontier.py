#!/usr/bin/env python3
"""Host-only Experiment 033: bounded residual-memory frontier extension.

This experiment is deliberately a narrow v4 extension of the frozen
Experiment 032 transform.  It consumes the exact 032 public result, hashes
and semantically validates both 032 bytes before importing the already-hashed
module, and visits only the same 71 bounded site ranges.  It preserves every
032 arithmetic/scalar/direct-control record exactly, then adds only the exact
reached integer residual forms qualified against Arm DDI0602 (ID092025):
signed-offset LDP/STP W/X, reached LDP X post-index, LDRSW X, LDRSB W, and
the exact DAIFClr IRQ/PSTATE-only system boundary.

Pair loads are conservative pre-state two-destination definitions and pair
stores always publish two explicit lane observations.  Sign-extending loads
define their destination locally and preserve DCB-derived data only when the
lattice proves it sound.  Post-index writeback is modulo 64 bits and overlap
hazards fail closed.  Pre-index, SIMD/FP, LDPSW, reserved or
constrained-unpredictable overlaps, other system forms, indirect aliases,
malformed forms, and unknown values remain fail-closed.  This is a
transform-only record: it never establishes a runtime destination or a global
consumer/writer absence claim.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
import struct
import sys
import types
from dataclasses import dataclass, replace
from importlib.machinery import ModuleSpec
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
MANIFEST_DIR = REPO_ROOT / "evidence/manifests"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"
MASK64 = 0xFFFFFFFFFFFFFFFF

EXPERIMENT_032_TOOL_NAME = "sm8150_dcb_arithmetic_frontier.py"
EXPERIMENT_032_TOOL_SIZE = 127_151
EXPERIMENT_032_TOOL_SHA256 = "d4233d08ebe3c28cf803f5e9e1e564f1d9e40af12eca85498d23e569821219e2"
EXPERIMENT_032_MANIFEST_NAME = "032-dcb-arithmetic-frontier-20260826-01.manifest.json"
EXPERIMENT_032_MANIFEST_SIZE = 1_564_295
EXPERIMENT_032_MANIFEST_SHA256 = "beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31"

# The 031/027/029 pins remain visible in the v4 public record through the
# exact 032 dependency.  Keeping their constants here also makes the
# dependency chain auditable by hostile tests without importing 032 first.
EXPERIMENT_031_TOOL_NAME = "sm8150_dcb_consumer_writer_extension.py"
EXPERIMENT_031_TOOL_SIZE = 91_221
EXPERIMENT_031_TOOL_SHA256 = "5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b"
EXPERIMENT_031_MANIFEST_NAME = "031-dcb-scalar-frontier-extension-20260826-01.manifest.json"
EXPERIMENT_031_MANIFEST_SIZE = 1_327_118
EXPERIMENT_031_MANIFEST_SHA256 = "51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86"

EXPERIMENT_027_TOOL_NAME = "sm8150_dcb_consumer_writer_complement.py"
EXPERIMENT_027_TOOL_SIZE = 86_782
EXPERIMENT_027_TOOL_SHA256 = "11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9"
EXPERIMENT_027_MANIFEST_NAME = "027-dcb-consumer-writer-complement-20260826-01.manifest.json"
EXPERIMENT_027_MANIFEST_SIZE = 334_847
EXPERIMENT_027_MANIFEST_SHA256 = "d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277"

EXPERIMENT_029_TOOL_NAME = "sm8150_dcb_unsupported_frontier.py"
EXPERIMENT_029_TOOL_SIZE = 43_950
EXPERIMENT_029_TOOL_SHA256 = "e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0"
EXPERIMENT_029_MANIFEST_NAME = "029-dcb-unsupported-frontier-20260826-01.manifest.json"
EXPERIMENT_029_MANIFEST_SIZE = 628_525
EXPERIMENT_029_MANIFEST_SHA256 = "c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634"

SCHEMA = "sm8150-dcb-residual-memory-frontier-v4"
EXPERIMENT_ID = "033-dcb-residual-memory-frontier"
MODE = "HOST_ONLY_READ_ONLY"

EXPERIMENT_032_ID = "032-dcb-arithmetic-frontier"
PAIR_MEMORY = "PAIR_MEMORY"
SIGN_EXTENDING_MEMORY = "SIGN_EXTENDING_MEMORY"
SYSTEM_CONTROL = "SYSTEM_CONTROL"

FLAG_ONLY_NO_GPR_DEF = "FLAG_ONLY_NO_GPR_DEF"
TAINT_KILL_REQUIRED = "TAINT_KILL_REQUIRED"
DECODER_EXTENSION_CANDIDATE = "DECODER_EXTENSION_CANDIDATE"
CONTROL_OR_MEMORY_UNSUPPORTED = "CONTROL_OR_MEMORY_UNSUPPORTED"
UNKNOWN = "UNKNOWN"
INDIRECT = "INDIRECT_OR_UNSUPPORTED"

V2_PREDICTED_IMPLEMENTED_FAMILIES = frozenset(
    {
        "ADDS_SUBS_IMM_FLAG",
        "ADDS_SUBS_REG_FLAG",
        "ADDS_SUBS_EXT_FLAG",
        "ANDS_IMM",
        "ANDS_SHIFT",
        "CCMP_CCMN",
        "ADDS_SUBS_IMM",
        "ADD_SUB_IMM_SP",
        "VARIABLE_SHIFT",
        "DIVIDE",
        "CONDITIONAL_SELECT",
        "BITFIELD_IMM",
        "AND_SHIFT",
    }
)

ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES = frozenset(
    {"THREE_SOURCE_UNVALIDATED", "EOR_SHIFT", "BIC_SHIFT"}
)

RESIDUAL_MEMORY_PREDICTED_FAMILIES = frozenset(
    {PAIR_MEMORY, SIGN_EXTENDING_MEMORY, SYSTEM_CONTROL}
)

PREDICTED_IMPLEMENTED_FAMILIES = frozenset(
    V2_PREDICTED_IMPLEMENTED_FAMILIES
    | ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES
    | RESIDUAL_MEMORY_PREDICTED_FAMILIES
)

# The source is a single official Arm primary-source release.  The URL is
# kept canonical and the immutable downloaded-source identity is pinned in
# the public manifest; the PDF itself is intentionally not copied into this
# repository.
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

ARM_FORM_SOURCES = {
    "FLAG_ONLY_NO_GPR_DEF": {"sections": ["ADDS extended register", "SUBS extended register", "ADDS immediate", "SUBS immediate", "ADDS shifted register", "SUBS shifted register", "ANDS immediate", "ANDS shifted register", "CCMN immediate", "CCMN register", "CCMP immediate", "CCMP register"], "pages": [25, 27, 28, 29, 34, 35, 113, 114, 116, 117, 827, 829, 830, 831], "promoted_forms": ["ADDS/SUBS Rd=31 flag aliases", "ANDS/TST", "CCMN/CCMP"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "BITFIELD_IMM": {"sections": ["BFM", "SBFM", "UBFM", "DecodeBitMasks"], "pages": [59, 647, 868, 4519, 4520], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "AND_SHIFT": {"sections": ["AND shifted register", "ShiftReg"], "pages": [33], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "THREE_SOURCE_UNVALIDATED": {"sections": ["MADD", "UMADDL"], "pages": [539, 873], "promoted_forms": ["MADD", "UMADDL"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "EOR_SHIFT": {"sections": ["EOR shifted register", "ShiftReg"], "pages": [354], "promoted_forms": ["EOR shifted register"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "BIC_SHIFT": {"sections": ["BIC shifted register", "ShiftReg"], "pages": [62], "promoted_forms": ["BIC shifted register"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "PAIR_MEMORY": {"sections": ["LDP", "STP"], "pages": [437, 438, 439, 752, 753, 754], "promoted_forms": ["LDP W/X signed offset", "LDP X post-index", "STP W/X signed offset"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "SIGN_EXTENDING_MEMORY": {"sections": ["LDRSB immediate", "LDRSW immediate"], "pages": [457, 458, 465, 466], "promoted_forms": ["LDRSB W unsigned immediate", "LDRSW X unsigned immediate"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "SYSTEM_CONTROL": {"sections": ["MSR immediate", "DAIFClr"], "pages": [553, 554, 555, 556], "promoted_forms": ["DAIFClr #IRQ exact side-effect boundary"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "TAINT_KILL_REQUIRED": {"sections": ["ADD immediate", "SUB immediate", "ADDS immediate", "SUBS immediate", "CSEL", "CSINC", "ASRV", "LSLV", "LSRV", "RORV", "SDIV", "UDIV"], "pages": [21, 27, 39, 325, 331, 535, 538, 640, 650, 820, 829, 872], "promoted_forms": ["ADDS/SUBS destination-local kill", "ADD/SUB SP destination-local kill", "CSEL/CSINC family kill", "variable shifts", "SDIV/UDIV"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
    "DIRECT_CONTROL_DISPATCH_REPAIR": {"sections": ["B", "B.cond", "CBNZ", "CBZ", "TBNZ", "TBZ"], "pages": [54, 55, 111, 112, 849, 850], "promoted_forms": ["bounded direct CFG dispatch only; no runtime target authority"], "source_url": "https://developer.arm.com/documentation/ddi0602/2025-09/", "document_identifier": "DDI0602 (ID092025)", "source_access_status": "AVAILABLE_AND_HASH_PINNED"},
}


class ExtensionError(ValueError):
    """Raised for an exact-input, semantic, or fail-closed violation."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value: int) -> str:
    return f"0x{value:08x}"


def sign_extend(value: int, bits: int) -> int:
    """Return the architectural signed interpretation of a bitfield."""

    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def parse_hex(value: Any, label: str) -> int:
    if not isinstance(value, str) or not value.lower().startswith("0x"):
        raise ExtensionError(f"{label} is not a hexadecimal string")
    try:
        result = int(value, 16)
    except ValueError as exc:
        raise ExtensionError(f"{label} is not hexadecimal") from exc
    if result < 0 or result > 0xFFFFFFFFFFFFFFFF:
        raise ExtensionError(f"{label} is outside the supported address width")
    return result


def load_exact(path: Path, size: int, digest: str, label: str) -> bytes:
    path = Path(path)
    if not path.is_file():
        raise ExtensionError(f"missing exact input: {label}")
    data = path.read_bytes()
    actual = sha256(data)
    if len(data) != size or actual != digest:
        raise ExtensionError(f"exact input mismatch: {label}")
    return data


def _validate_031_manifest(manifest: Mapping[str, Any]) -> None:
    """Validate the committed 031 contract before using its site results."""

    if manifest.get("experiment_id") != "031-dcb-scalar-frontier-extension" or manifest.get("mode") != MODE:
        raise ExtensionError("Experiment 031 identity/mode changed")
    if manifest.get("classification") != "CLASS C (TRANSFORM ONLY)" or manifest.get("device_access") != "none" or manifest.get("eligibility") != "NOT_ELIGIBLE":
        raise ExtensionError("Experiment 031 authority boundary changed")
    firmware = manifest.get("inputs", {}).get("firmware", {})
    if firmware != {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}:
        raise ExtensionError("Experiment 031 exact firmware pin changed")
    scope = manifest.get("scope")
    analysis = manifest.get("analysis")
    sites = manifest.get("sites")
    if not isinstance(scope, Mapping) or not isinstance(analysis, Mapping) or not isinstance(sites, list) or len(sites) != 71:
        raise ExtensionError("Experiment 031 site contract is malformed")
    if (
        scope.get("fail_closed_site_count") != 71
        or scope.get("arbitrary_range_scan") is not False
        or scope.get("device_mmio_write") is not False
        or scope.get("global_writer_absence") != "UNKNOWN"
        or scope.get("writer_absence_claim") is not False
        or scope.get("direct_control_dispatch_repair") != "DIRECT_CONTROL_DISPATCH_REPAIR"
    ):
        raise ExtensionError("Experiment 031 scope contract changed")
    delta = analysis.get("actual_delta_vs_027", {})
    if (
        delta.get("baseline_fail_closed_sites") != 71
        or delta.get("sites_transitioned_to_no_target_within_v2_model") != 51
        or delta.get("sites_remaining_fail_closed") != 20
        or delta.get("v2_fail_closed_sites") != 20
        or delta.get("transition_scope") != "V2_MODEL_ONLY"
        or delta.get("absence_claim") != "NO_ABSENCE_CLAIM"
        or delta.get("combined_scalar_plus_dispatch_v2") is not True
    ):
        raise ExtensionError("Experiment 031 bounded transition contract changed")
    dispatch = analysis.get("direct_control_dispatch_repair", {})
    if (
        dispatch.get("event_count") != 143
        or dispatch.get("site_count") != 62
        or dispatch.get("family_counts") != {"B": 15, "B.cond": 87, "CBZ_CBNZ": 28, "TBZ_TBNZ": 13}
        or dispatch.get("identity_check") is not True
    ):
        raise ExtensionError("Experiment 031 direct-control repair contract changed")
    admission = analysis.get("extension_admission", {})
    if (
        admission.get("selected_029_occurrence_count") != 283
        or admission.get("reached_unique_event_count") != 250
        or admission.get("selected_not_reached_count") != 33
        or admission.get("events_outside_selected") != 0
        or admission.get("family_mismatch_count") != 0
        or admission.get("label_mismatch_count") != 0
        or admission.get("all_reached_events_admitted") is not True
        or admission.get("exact_selected_identity") is not True
    ):
        raise ExtensionError("Experiment 031 admission contract changed")
    discriminators = analysis.get("discriminator_counts", {})
    if discriminators.get(INDIRECT) != 20 or discriminators.get("NO_TARGET_WITHIN_MODEL") != 51:
        raise ExtensionError("Experiment 031 discriminator accounting changed")
    if discriminators.get("DCB_CONSUMER_PATH", 0) != 0 or discriminators.get("MC_OR_SHRM_SYMBOLIC_TARGET", 0) != 0:
        raise ExtensionError("Experiment 031 consumer/target boundary changed")
    if analysis.get("writer_absence") != "UNKNOWN" or analysis.get("writer_absence_claim") is not False:
        raise ExtensionError("Experiment 031 writer boundary changed")


def validate_031_manifest(manifest: Mapping[str, Any]) -> None:
    """Public semantic validator used by focused and hostile tests."""

    _validate_031_manifest(manifest)


def _validate_027_manifest(manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment_id") != "027-dcb-consumer-writer-complement" or manifest.get("mode") != MODE:
        raise ExtensionError("Experiment 027 identity/mode changed")
    if manifest.get("classification") != "CLASS C (TRANSFORM ONLY)" or manifest.get("device_access") != "none" or manifest.get("eligibility") != "NOT_ELIGIBLE":
        raise ExtensionError("Experiment 027 authority boundary changed")
    firmware = manifest.get("inputs", {}).get("firmware", {})
    if firmware != {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}:
        raise ExtensionError("Experiment 027 exact firmware pin changed")
    summary = manifest.get("site_summary")
    scope = manifest.get("scope")
    sites = manifest.get("sites")
    if not isinstance(summary, Mapping) or not isinstance(scope, Mapping) or not isinstance(sites, list):
        raise ExtensionError("Experiment 027 site contract is malformed")
    if summary.get("site_count") != 73 or summary.get("register_offset_site_count") != 65 or summary.get("computed_address_site_count") != 8 or len(sites) != 73:
        raise ExtensionError("Experiment 027 site cardinality changed")
    if scope.get("register_offset_sites") != 67 or scope.get("computed_address_idioms") != 8 or scope.get("global_writer_absence") != "UNKNOWN" or scope.get("writer_absence_claim") is not False:
        raise ExtensionError("Experiment 027 scope contract changed")
    fail_closed = [row for row in sites if isinstance(row, Mapping) and INDIRECT in row.get("discriminators", [])]
    if len(fail_closed) != 71:
        raise ExtensionError("Experiment 027 exact fail-closed site count changed")
    counts: dict[str, int] = {}
    for row in sites:
        if not isinstance(row, Mapping) or not isinstance(row.get("discriminators"), list):
            raise ExtensionError("Experiment 027 site row is malformed")
        for label in row["discriminators"]:
            counts[label] = counts.get(label, 0) + 1
    if counts.get(INDIRECT) != 71 or counts.get("NO_TARGET_WITHIN_MODEL") != 2:
        raise ExtensionError("Experiment 027 discriminator accounting changed")
    if summary.get("writer_absence") != "UNKNOWN" or summary.get("writer_absence_claim") is not False:
        raise ExtensionError("Experiment 027 writer boundary changed")


def _validate_029_manifest(manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment_id") != "029-dcb-unsupported-frontier" or manifest.get("mode") != MODE:
        raise ExtensionError("Experiment 029 identity/mode changed")
    if manifest.get("classification") != "CLASS C (TRANSFORM ONLY)" or manifest.get("device_access") != "none" or manifest.get("eligibility") != "NOT_ELIGIBLE":
        raise ExtensionError("Experiment 029 authority boundary changed")
    firmware = manifest.get("inputs", {}).get("firmware", {})
    if firmware != {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}:
        raise ExtensionError("Experiment 029 firmware pin changed")
    dep = manifest.get("dependency_027_semantics", {})
    if dep.get("site_count") != 73 or dep.get("indirect_or_unsupported") != 71 or dep.get("writer_absence") != "UNKNOWN" or dep.get("writer_absence_claim") is not False:
        raise ExtensionError("Experiment 029 dependency boundary changed")
    scope = manifest.get("scope", {})
    if scope.get("fail_closed_site_count") != 71 or scope.get("cfg_reachability") != "UNKNOWN_NOT_ANALYZED" or scope.get("arbitrary_range_scan") is not False or scope.get("device_mmio_write") is not False:
        raise ExtensionError("Experiment 029 scope boundary changed")
    ranges = manifest.get("site_ranges")
    frontier = manifest.get("frontier", {})
    occurrences = frontier.get("occurrences")
    if not isinstance(ranges, list) or len(ranges) != 71 or not isinstance(occurrences, list) or len(occurrences) != 352:
        raise ExtensionError("Experiment 029 exact range/occurrence cardinality changed")
    accounting = manifest.get("accounting", {})
    expected = {
        "site_count": 71,
        "scanned_word_occurrence_count": 1992,
        "scanned_unique_va_count": 1180,
        "recognized_word_occurrence_count": 1640,
        "frontier_occurrence_count": 352,
        "frontier_unique_va_count": 219,
        "frontier_unique_raw_word_count": 197,
    }
    if any(accounting.get(key) != value for key, value in expected.items()):
        raise ExtensionError("Experiment 029 accounting changed")
    classes = frontier.get("class_counts")
    if classes != {"CONTROL_OR_MEMORY_UNSUPPORTED": 54, "DECODER_EXTENSION_CANDIDATE": 161, "FLAG_ONLY_NO_GPR_DEF": 99, "TAINT_KILL_REQUIRED": 27, "UNKNOWN": 11}:
        raise ExtensionError("Experiment 029 class accounting changed")
    for row in ranges:
        if not isinstance(row, Mapping) or not isinstance(row.get("site_index"), int) or not isinstance(row.get("site_range"), Mapping):
            raise ExtensionError("Experiment 029 site range row is malformed")
    for occurrence in occurrences:
        if not isinstance(occurrence, Mapping) or not isinstance(occurrence.get("classification"), Mapping):
            raise ExtensionError("Experiment 029 frontier row is malformed")
        if occurrence["classification"].get("source_provenance") != "UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW":
            raise ExtensionError("Experiment 029 source provenance boundary changed")
        if occurrence["classification"].get("reachability") != "UNKNOWN_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY" or occurrence["classification"].get("decoder_safety") != "NOT_CLAIMED":
            raise ExtensionError("Experiment 029 reachability/safety boundary changed")


def _import_source_bytes(data: bytes, path: Path, digest: str, label: str) -> Any:
    """Execute the already-hashed source bytes without reopening ``path``.

    A path is retained only as provenance for ``__file__`` and ``__spec__``.
    The module is registered before execution so code using normal module
    metadata sees a useful identity, while the source itself can never change
    between the hash check and ``exec``.
    """

    module_name = f"_sm8150_{label.lower().replace(' ', '_')}_pinned_{digest[:16]}"
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


def _import_031(data: bytes, path: Path, digest: str) -> Any:
    """Import 031 from the exact bytes that passed its pin gate."""

    return _import_source_bytes(data, path, digest, "exp031")


def _import_027(data: bytes, path: Path, digest: str) -> Any:
    """Import 027 from the exact bytes that passed its pin gate."""

    return _import_source_bytes(data, path, digest, "exp027")


def _load_legacy_031_dependencies(
    *,
    tool_031_path: Path | None = None,
    manifest_031_path: Path | None = None,
    tool_027_path: Path | None = None,
    manifest_027_path: Path | None = None,
    tool_029_path: Path | None = None,
    manifest_029_path: Path | None = None,

) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Pin 031/027/029 bytes and semantics before importing any dependency."""

    tool_031_path = Path(tool_031_path) if tool_031_path is not None else REPO_ROOT / "tools" / EXPERIMENT_031_TOOL_NAME
    manifest_031_path = Path(manifest_031_path) if manifest_031_path is not None else MANIFEST_DIR / EXPERIMENT_031_MANIFEST_NAME
    tool_027_path = Path(tool_027_path) if tool_027_path is not None else REPO_ROOT / "tools" / EXPERIMENT_027_TOOL_NAME
    manifest_027_path = Path(manifest_027_path) if manifest_027_path is not None else MANIFEST_DIR / EXPERIMENT_027_MANIFEST_NAME
    tool_029_path = Path(tool_029_path) if tool_029_path is not None else REPO_ROOT / "tools" / EXPERIMENT_029_TOOL_NAME
    manifest_029_path = Path(manifest_029_path) if manifest_029_path is not None else MANIFEST_DIR / EXPERIMENT_029_MANIFEST_NAME

    # All source/public bytes are validated before any source import.  This ordering is
    # an intentional hostile-dependency boundary.
    tool_031_data = load_exact(tool_031_path, EXPERIMENT_031_TOOL_SIZE, EXPERIMENT_031_TOOL_SHA256, EXPERIMENT_031_TOOL_NAME)
    manifest_031_data = load_exact(manifest_031_path, EXPERIMENT_031_MANIFEST_SIZE, EXPERIMENT_031_MANIFEST_SHA256, EXPERIMENT_031_MANIFEST_NAME)
    tool_027_data = load_exact(tool_027_path, EXPERIMENT_027_TOOL_SIZE, EXPERIMENT_027_TOOL_SHA256, EXPERIMENT_027_TOOL_NAME)
    manifest_027_data = load_exact(manifest_027_path, EXPERIMENT_027_MANIFEST_SIZE, EXPERIMENT_027_MANIFEST_SHA256, EXPERIMENT_027_MANIFEST_NAME)
    tool_029_data = load_exact(tool_029_path, EXPERIMENT_029_TOOL_SIZE, EXPERIMENT_029_TOOL_SHA256, EXPERIMENT_029_TOOL_NAME)
    manifest_029_data = load_exact(manifest_029_path, EXPERIMENT_029_MANIFEST_SIZE, EXPERIMENT_029_MANIFEST_SHA256, EXPERIMENT_029_MANIFEST_NAME)
    try:
        manifest_031 = json.loads(manifest_031_data)
        manifest_027 = json.loads(manifest_027_data)
        manifest_029 = json.loads(manifest_029_data)
    except json.JSONDecodeError as exc:
        raise ExtensionError("pinned dependency is not JSON") from exc
    if not isinstance(manifest_031, dict) or not isinstance(manifest_027, dict) or not isinstance(manifest_029, dict):
        raise ExtensionError("pinned dependency root is not an object")
    _validate_031_manifest(manifest_031)
    _validate_027_manifest(manifest_027)
    _validate_029_manifest(manifest_029)
    _import_031(tool_031_data, tool_031_path, EXPERIMENT_031_TOOL_SHA256)
    decoder = _import_027(tool_027_data, tool_027_path, EXPERIMENT_027_TOOL_SHA256)
    hashes = {
        "experiment_031_tool": {"filename": EXPERIMENT_031_TOOL_NAME, "size": len(tool_031_data), "sha256": sha256(tool_031_data)},
        "experiment_031_manifest": {"filename": EXPERIMENT_031_MANIFEST_NAME, "size": len(manifest_031_data), "sha256": sha256(manifest_031_data)},
        "experiment_027_tool": {"filename": EXPERIMENT_027_TOOL_NAME, "size": len(tool_027_data), "sha256": sha256(tool_027_data)},
        "experiment_027_manifest": {"filename": EXPERIMENT_027_MANIFEST_NAME, "size": len(manifest_027_data), "sha256": sha256(manifest_027_data)},
        "experiment_029_tool": {"filename": EXPERIMENT_029_TOOL_NAME, "size": len(tool_029_data), "sha256": sha256(tool_029_data)},
        "experiment_029_manifest": {"filename": EXPERIMENT_029_MANIFEST_NAME, "size": len(manifest_029_data), "sha256": sha256(manifest_029_data)},
    }
    return decoder, manifest_031, manifest_029, hashes


def _validate_legacy_031_dependencies(manifest_027: Mapping[str, Any], manifest_029: Mapping[str, Any]) -> None:
    """Public semantic validator used by focused and hostile tests."""

    _validate_027_manifest(manifest_027)
    _validate_029_manifest(manifest_029)


# ---------------------------------------------------------------------------
# Frozen Experiment 032 dependency gate


def _validate_032_manifest(manifest: Mapping[str, Any]) -> None:
    """Validate the committed 032 contract before importing its bytes.

    The v4 transform is admitted only from the exact 032 result.  These are
    semantic pins in addition to the byte hash: a same-sized mutation that
    preserves JSON shape must still fail before executing the dependency.
    """

    if manifest.get("experiment_id") != EXPERIMENT_032_ID or manifest.get("schema") != "sm8150-dcb-arithmetic-frontier-v3":
        raise ExtensionError("Experiment 032 identity/schema changed")
    if manifest.get("mode") != MODE or manifest.get("classification") != "CLASS C (TRANSFORM ONLY)" or manifest.get("device_access") != "none" or manifest.get("eligibility") != "NOT_ELIGIBLE":
        raise ExtensionError("Experiment 032 authority boundary changed")
    firmware = manifest.get("inputs", {}).get("firmware", {})
    if firmware != {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}:
        raise ExtensionError("Experiment 032 firmware pin changed")
    analysis = manifest.get("analysis")
    sites = manifest.get("sites")
    scope = manifest.get("scope")
    if not isinstance(analysis, Mapping) or not isinstance(sites, list) or len(sites) != 71 or not isinstance(scope, Mapping):
        raise ExtensionError("Experiment 032 site contract is malformed")
    if analysis.get("site_count") != 71:
        raise ExtensionError("Experiment 032 site count changed")
    if analysis.get("discriminator_counts") != {"DCB_CONSUMER_PATH": 0, "INDIRECT_OR_UNSUPPORTED": 16, "MC_OR_SHRM_SYMBOLIC_TARGET": 0, "NO_TARGET_WITHIN_MODEL": 55}:
        raise ExtensionError("Experiment 032 55/16 discriminator accounting changed")
    selected = analysis.get("selected_syntactic_frontier", {})
    if selected.get("occurrence_count") != 298:
        raise ExtensionError("Experiment 032 selected frontier cardinality changed")
    remaining = analysis.get("remaining_syntactic_frontier", {})
    if remaining.get("occurrence_count") != 54:
        raise ExtensionError("Experiment 032 residual frontier cardinality changed")
    if analysis.get("all_range_forms_selected", {}).get("ratio") != "56/71":
        raise ExtensionError("Experiment 032 range-selection ratio changed")
    delta = analysis.get("actual_delta_vs_027", {})
    if (
        delta.get("v3_fail_closed_sites") != 16
        or delta.get("sites_remaining_fail_closed") != 16
        or delta.get("sites_transitioned_to_no_target_within_v3_model") != 55
        or delta.get("transition_identity") is not True
        or delta.get("transition_scope") != "V3_MODEL_ONLY"
        or delta.get("absence_claim") != "NO_ABSENCE_CLAIM"
    ):
        raise ExtensionError("Experiment 032 55/16 transition contract changed")
    quadrants = analysis.get("transition_quadrants", {})
    expected_quadrants = {
        "031_INDIRECT_OR_UNSUPPORTED_TO_032_INDIRECT_OR_UNSUPPORTED": 16,
        "031_INDIRECT_OR_UNSUPPORTED_TO_032_NO_TARGET_WITHIN_MODEL": 4,
        "031_NO_TARGET_WITHIN_MODEL_TO_032_INDIRECT_OR_UNSUPPORTED": 0,
        "031_NO_TARGET_WITHIN_MODEL_TO_032_NO_TARGET_WITHIN_MODEL": 51,
    }
    if quadrants.get("counts") != expected_quadrants or quadrants.get("identity_check") is not True or quadrants.get("regression_free") is not True:
        raise ExtensionError("Experiment 032 transition quadrants changed")
    equivalence = analysis.get("inherited_031_equivalence", {})
    if equivalence.get("all_checks_exact") is not True:
        raise ExtensionError("Experiment 032 inherited equivalence gate is not exact")
    for name, count in (("reached_extension_events", 250), ("direct_control_events", 143), ("reached_taint_kill_events", 23)):
        row = equivalence.get(name, {})
        if row.get("expected_count") != count or row.get("actual_count") != count or row.get("exact_full_record_equality") is not True:
            raise ExtensionError(f"Experiment 032 inherited {name} equivalence changed")
    expected_equivalence_hashes = {
        "reached_extension_events": "1225b8e3f9d73f76f0db6cafdb69322e5b14164b3c071efb32bcf47682291b95",
        "direct_control_events": "83e9f5415c1733ebb4f1ade5fdbeb3bb202fb92d60195ba5393917a5c54f273f",
        "reached_taint_kill_events": "ec8f8e9186c1034182f95bce699649e2d2e2a44058a61588e9d3b5d3dd1fc1fa",
    }
    for name, digest in expected_equivalence_hashes.items():
        row = equivalence.get(name, {})
        if row.get("expected_canonical_sha256") != digest or row.get("actual_canonical_sha256") != digest:
            raise ExtensionError(f"Experiment 032 inherited {name} canonical hash changed")
    operation_counts = analysis.get("arithmetic_operation_counts", {})
    if operation_counts.get("counts") != {"BIC": 2, "EOR": 2, "MADD": 3, "UMADDL": 7} or operation_counts.get("identity_check") is not True:
        raise ExtensionError("Experiment 032 arithmetic operation accounting changed")
    if analysis.get("reached_extension_event_count") != 264 or analysis.get("reached_arithmetic_event_count") != 14:
        raise ExtensionError("Experiment 032 reached-event accounting changed")
    top_events = analysis.get("reached_extension_events")
    if not isinstance(top_events, list) or len(top_events) != 264:
        raise ExtensionError("Experiment 032 complete reached-event ledger changed")
    top_event_digest = sha256(("\n".join(_canonical_records(top_events)) + "\n").encode())
    if top_event_digest != "248812896ae085b4204abc798ab103d48726d7b7eac32eca556130491dc8b94f":
        raise ExtensionError("Experiment 032 complete reached-event canonical identity changed")
    admission = analysis.get("extension_admission", {})
    if admission.get("selected_029_occurrence_count") != 298 or admission.get("reached_unique_event_count") != 264 or admission.get("selected_not_reached_count") != 34 or admission.get("all_reached_events_admitted") is not True:
        raise ExtensionError("Experiment 032 admission accounting changed")
    if analysis.get("writer_absence") != "UNKNOWN" or analysis.get("writer_absence_claim") is not False or scope.get("global_writer_absence") != "UNKNOWN" or scope.get("writer_absence_claim") is not False:
        raise ExtensionError("Experiment 032 writer boundary changed")


def validate_032_manifest(manifest: Mapping[str, Any]) -> None:
    """Public semantic validator for the frozen 032 dependency."""

    _validate_032_manifest(manifest)


def _import_032(data: bytes, path: Path, digest: str) -> Any:
    """Execute the exact, already-hashed 032 source bytes."""

    return _import_source_bytes(data, path, digest, "exp032")


def load_pinned_dependencies(
    *,
    tool_032_path: Path | None = None,
    manifest_032_path: Path | None = None,
    tool_031_path: Path | None = None,
    manifest_031_path: Path | None = None,
    tool_027_path: Path | None = None,
    manifest_027_path: Path | None = None,
    tool_029_path: Path | None = None,
    manifest_029_path: Path | None = None,
) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Pin/validate 032 before importing it, then use its pinned source chain.

    The four-tuple mirrors the prior frontier APIs: decoder, exact 032 public
    manifest, exact 029 frontier manifest, and a complete hash ledger.  The
    032 module itself is imported only from ``tool_032_data`` after both
    dependency bytes and the 032 semantic contract have passed their gates.
    """

    tool_032_path = Path(tool_032_path) if tool_032_path is not None else REPO_ROOT / "tools" / EXPERIMENT_032_TOOL_NAME
    manifest_032_path = Path(manifest_032_path) if manifest_032_path is not None else MANIFEST_DIR / EXPERIMENT_032_MANIFEST_NAME
    tool_032_data = load_exact(tool_032_path, EXPERIMENT_032_TOOL_SIZE, EXPERIMENT_032_TOOL_SHA256, EXPERIMENT_032_TOOL_NAME)
    manifest_032_data = load_exact(manifest_032_path, EXPERIMENT_032_MANIFEST_SIZE, EXPERIMENT_032_MANIFEST_SHA256, EXPERIMENT_032_MANIFEST_NAME)
    try:
        manifest_032 = json.loads(manifest_032_data)
    except json.JSONDecodeError as exc:
        raise ExtensionError("pinned Experiment 032 manifest is not JSON") from exc
    if not isinstance(manifest_032, dict):
        raise ExtensionError("pinned Experiment 032 manifest root is not an object")
    _validate_032_manifest(manifest_032)

    # Explicit paths keep a temporary/path-replacement hostile test from
    # changing which 031/027/029 bytes the pinned 032 module consumes.
    chain_tool_031 = Path(tool_031_path) if tool_031_path is not None else REPO_ROOT / "tools" / EXPERIMENT_031_TOOL_NAME
    chain_manifest_031 = Path(manifest_031_path) if manifest_031_path is not None else MANIFEST_DIR / EXPERIMENT_031_MANIFEST_NAME
    chain_tool_027 = Path(tool_027_path) if tool_027_path is not None else REPO_ROOT / "tools" / EXPERIMENT_027_TOOL_NAME
    chain_manifest_027 = Path(manifest_027_path) if manifest_027_path is not None else MANIFEST_DIR / EXPERIMENT_027_MANIFEST_NAME
    chain_tool_029 = Path(tool_029_path) if tool_029_path is not None else REPO_ROOT / "tools" / EXPERIMENT_029_TOOL_NAME
    chain_manifest_029 = Path(manifest_029_path) if manifest_029_path is not None else MANIFEST_DIR / EXPERIMENT_029_MANIFEST_NAME

    pinned_032 = _import_032(tool_032_data, tool_032_path, EXPERIMENT_032_TOOL_SHA256)
    decoder, _manifest_031, manifest_029, chain_hashes = pinned_032.load_pinned_dependencies(
        tool_031_path=chain_tool_031,
        manifest_031_path=chain_manifest_031,
        tool_027_path=chain_tool_027,
        manifest_027_path=chain_manifest_027,
        tool_029_path=chain_tool_029,
        manifest_029_path=chain_manifest_029,
    )
    hashes = {
        "experiment_032_tool": {"filename": EXPERIMENT_032_TOOL_NAME, "size": len(tool_032_data), "sha256": sha256(tool_032_data)},
        "experiment_032_manifest": {"filename": EXPERIMENT_032_MANIFEST_NAME, "size": len(manifest_032_data), "sha256": sha256(manifest_032_data)},
        **chain_hashes,
    }
    return decoder, manifest_032, manifest_029, hashes


# ---------------------------------------------------------------------------
# Exact A64 scalar decoding helpers


def _shift_value(value: int, width: int, kind: int, amount: int) -> int | None:
    if amount >= width or kind not in (0, 1, 2, 3):
        return None
    mask = (1 << width) - 1
    value &= mask
    if kind == 0:
        return (value << amount) & mask
    if kind == 1:
        return value >> amount
    if kind == 2:
        signed = value - (1 << width) if value & (1 << (width - 1)) else value
        return (signed >> amount) & mask
    if amount == 0:
        return value
    return ((value >> amount) | (value << (width - amount))) & mask


def _decode_shifted_logical(word: int) -> tuple[str, bool, int, int, int, int, int, int] | None:
    names = {
        0x0A000000: "AND_SHIFT",
        0x0A200000: "BIC_SHIFT",
        0x2A000000: "ORR_SHIFT",
        0x2A200000: "ORN_SHIFT",
        0x4A000000: "EOR_SHIFT",
        0x4A200000: "EON_SHIFT",
        0x6A000000: "ANDS_SHIFT",
        0x6A200000: "BICS_SHIFT",
        0x8A000000: "AND_SHIFT",
        0x8A200000: "BIC_SHIFT",
        0xAA000000: "ORR_SHIFT",
        0xAA200000: "ORN_SHIFT",
        0xCA000000: "EOR_SHIFT",
        0xCA200000: "EON_SHIFT",
        0xEA000000: "ANDS_SHIFT",
        0xEA200000: "BICS_SHIFT",
    }
    if (word & 0x1F000000) != 0x0A000000:
        return None
    base = word & 0xFF200000
    family = names.get(base)
    if family is None:
        return None
    sf = 1 if word & 0x80000000 else 0
    width = 64 if sf else 32
    shift_kind = (word >> 22) & 3
    amount = (word >> 10) & 0x3F
    valid = amount < width
    return family, bool(valid), width, shift_kind, amount, (word >> 16) & 0x1F, (word >> 5) & 0x1F, word & 0x1F


def _decode_logical_immediate(word: int, decoder: Any) -> tuple[str, bool, int, int, int, int] | None:
    names = {0x12000000: "AND_IMM", 0x32000000: "ORR_IMM", 0x52000000: "EOR_IMM", 0x72000000: "ANDS_IMM"}
    base = word & 0x7F800000
    family = names.get(base)
    if family is None:
        return None
    sf = 1 if word & 0x80000000 else 0
    width = 64 if sf else 32
    n = (word >> 22) & 1
    value = decoder._decode_logical_immediate(n, (word >> 16) & 0x3F, (word >> 10) & 0x3F, width)
    valid = not (width == 32 and n) and value is not None
    return family, valid, width, word & 0x1F, (word >> 5) & 0x1F, value if value is not None else 0


def _decode_add_sub_immediate(word: int) -> tuple[str, bool, int, bool, int, int, int, int] | None:
    if (word & 0x1F000000) not in (0x11000000, 0x51000000, 0x91000000, 0xD1000000):
        return None
    if word & 0x00800000:
        return "ADD_SUB_IMM_TAGGED_OR_RESERVED", False, 64 if word & 0x80000000 else 32, bool(word & 0x20000000), word & 0x1F, (word >> 5) & 0x1F, 0, 0
    width = 64 if word & 0x80000000 else 32
    s = bool(word & 0x20000000)
    rd, rn = word & 0x1F, (word >> 5) & 0x1F
    imm = (word >> 10) & 0xFFF
    if word & (1 << 22):
        imm <<= 12
    return "ADD_SUB_IMM", True, width, s, rd, rn, imm, 1 if word & 0x40000000 else 0


def _decode_add_sub_register(word: int) -> tuple[str, bool, int, bool, int, int, int, int, int, int] | None:
    if (word & 0x1F200000) not in (0x0B000000, 0x0B200000):
        return None
    width = 64 if word & 0x80000000 else 32
    s = bool(word & 0x20000000)
    rd, rn, rm = word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F
    if word & 0x00200000:
        option = (word >> 13) & 7
        amount = (word >> 10) & 7
        valid_options = set(range(8)) if width == 64 else {0, 1, 2, 4, 5, 6}
        valid = not (word & 0x00C00000) and amount <= 4 and option in valid_options
        return "ADD_SUB_EXT", valid, width, s, rd, rn, rm, option, amount, 1 if word & 0x40000000 else 0
    shift_kind = (word >> 22) & 3
    amount = (word >> 10) & 0x3F
    valid = shift_kind != 3 and amount < width
    return "ADD_SUB_REG", valid, width, s, rd, rn, rm, shift_kind, amount, 1 if word & 0x40000000 else 0


def _decode_ccmp(word: int) -> tuple[str, bool, int, int, int, int] | None:
    if (word & 0x1FE00000) != 0x1A400000 or ((word >> 12) & 0xF) == 0xF:
        return None
    # The immediate and register variants both set NZCV only.  Keep the
    # exact field extraction for audit output; no GPR is ever defined.
    return "CCMP_CCMN", True, 64 if word & 0x80000000 else 32, (word >> 5) & 0x1F, (word >> 16) & 0x1F, (word >> 12) & 0xF


def _decode_bitfield(word: int) -> tuple[str, bool, int, int, int, int, int, int, int] | None:
    if (word & 0x1F800000) != 0x13000000:
        return None
    sf = 1 if word & 0x80000000 else 0
    n = (word >> 22) & 1
    opc = (word >> 29) & 3
    width = 64 if sf else 32
    immr, imms = (word >> 16) & 0x3F, (word >> 10) & 0x3F
    valid = opc != 3 and n == sf and immr < width and imms < width
    family = ("SBFM", "BFM", "UBFM")[opc] if opc < 3 else "BITFIELD_RESERVED_OPC"
    return family, valid, width, n, opc, immr, imms, (word >> 5) & 0x1F, word & 0x1F


def _decode_variable_shift(word: int) -> tuple[str, bool, int, int] | None:
    bases = {0x1AC02000: "LSLV", 0x1AC02400: "LSRV", 0x1AC02800: "ASRV", 0x1AC02C00: "RORV"}
    base = word & 0x1FE0FC00
    family = bases.get(base)
    if family is None:
        return None
    return family, True, word & 0x1F, (word >> 5) & 0x1F


def _decode_divide(word: int) -> tuple[str, bool, int] | None:
    base = word & 0x1FE0FC00
    family = {0x1AC00800: "UDIV", 0x1AC00C00: "SDIV"}.get(base)
    return None if family is None else (family, True, word & 0x1F)


def _decode_csel(word: int) -> tuple[str, bool, int, int, int] | None:
    if (word & 0x1FE00C00) not in (0x1A800000, 0x1A800400):
        return None
    if ((word >> 12) & 0xF) == 0xF:
        return None
    return "CSEL", True, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F


def _decode_three_source(word: int) -> tuple[str, bool, int, int, int, int, int, int] | None:
    """Decode only the architecturally-qualified MADD/UMADDL forms.

    The multiply/add class has a fixed ``0b11011`` opcode prefix.  The
    operation selector in bits 23:21 distinguishes MADD (000) and UMADDL
    (101); bit 15 is ``o0`` and must remain clear for an add.  Other members
    of the three-source class (MSUB, SMADDL/SMSUBL, UMSUBL, and reserved
    selectors) are returned as an explicit unsupported frontier row instead of
    being mistaken for MADD.
    """

    # Bits 30:24 are fixed by the multiply/add class; sf (bit 31) is the
    # width selector.  The strict mask also rejects unrelated data-processing
    # classes that happen to share the low 0x1b prefix.
    if (word & 0x7F000000) != 0x1B000000:
        return None
    sf = 1 if word & 0x80000000 else 0
    width = 64 if sf else 32
    opcode = word & 0x7FE08000
    selector = (word >> 21) & 0x7
    o0 = (word >> 15) & 0x1
    rm, ra, rn, rd = (word >> 16) & 0x1F, (word >> 10) & 0x1F, (word >> 5) & 0x1F, word & 0x1F
    if opcode == 0x1B000000:
        return "MADD", True, width, rm, ra, rn, rd, selector
    if opcode == 0x1BA00000 and sf:
        return "UMADDL", True, 64, rm, ra, rn, rd, selector
    return "THREE_SOURCE_UNVALIDATED", False, width, rm, ra, rn, rd, selector


def _three_source_dict(info: tuple[str, bool, int, int, int, int, int, int]) -> dict[str, Any]:
    family, valid, width, rm, ra, rn, rd, selector = info
    operation = family if family in {"MADD", "UMADDL"} else "UNVALIDATED"
    return {"family": "THREE_SOURCE_UNVALIDATED", "operation": operation, "width": width, "rm": rm, "ra": ra, "rn": rn, "rd": rd, "selector": selector, "valid": valid}


def decode_three_source(word: int) -> dict[str, Any] | None:
    """Return a source-gated public decode for valid MADD/UMADDL."""

    if not _arm_source_available():
        return None
    info = _decode_three_source(word)
    if info is None or not info[1]:
        return None
    return _three_source_dict(info)


def decode_madd(word: int) -> dict[str, Any] | None:
    info = decode_three_source(word)
    return info if info is not None and info["operation"] == "MADD" else None


def decode_umaddl(word: int) -> dict[str, Any] | None:
    info = decode_three_source(word)
    return info if info is not None and info["operation"] == "UMADDL" else None


def _classify_v3_word_impl(word: int, decoder: Any) -> dict[str, Any]:
    """Classify 031's exact scalar domain plus the v3 arithmetic frontier."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        raise ExtensionError("raw instruction word is not uint32")
    three = _decode_three_source(word)
    if three is not None:
        family, valid, width, rm, ra, rn, rd, selector = three
        if valid:
            return {"family": "THREE_SOURCE_UNVALIDATED", "operation": family, "label": DECODER_EXTENSION_CANDIDATE, "supported": True, "reason": "qualified MADD/UMADDL modulo-width arithmetic", "width": width, "rm": rm, "ra": ra, "rn": rn, "rd": rd, "selector": selector}
        return {"family": "THREE_SOURCE_UNVALIDATED", "operation": "UNVALIDATED", "label": UNKNOWN, "supported": False, "reason": "unsupported or reserved three-source operation selector", "width": width, "rm": rm, "ra": ra, "rn": rn, "rd": rd, "selector": selector}
    shifted = _decode_shifted_logical(word)
    if shifted is not None and shifted[0] in {"EOR_SHIFT", "BIC_SHIFT"}:
        family, valid, width, shift_type, amount, rm, rn, rd = shifted
        if valid:
            return {"family": family, "operation": family.removesuffix("_SHIFT"), "label": DECODER_EXTENSION_CANDIDATE, "supported": True, "reason": f"qualified {family} shifted-register semantics", "width": width, "shift_type": shift_type, "shift_amount": amount, "rn": rn, "rm": rm, "rd": rd}
        return {"family": family, "operation": family.removesuffix("_SHIFT"), "label": UNKNOWN, "supported": False, "reason": "invalid logical shifted width/amount", "width": width, "shift_type": shift_type, "shift_amount": amount, "rn": rn, "rm": rm, "rd": rd}
    return _classify_v2_word_impl(word, decoder)


def classify_v3_word(word: int, decoder: Any) -> dict[str, Any]:
    """Apply the same official-source gate used by 031 to v3 forms."""

    result = _classify_v3_word_impl(word, decoder)
    if result.get("supported") and not _arm_source_available():
        result = dict(result)
        result["supported"] = False
        result["label"] = UNKNOWN
        result["reason"] = "official Arm primary source unavailable; form remains UNKNOWN and fail-closed"
        result["source_access_status"] = "UNKNOWN_SOURCE_UNAVAILABLE"
    else:
        result["source_access_status"] = "AVAILABLE_AND_HASH_PINNED" if result.get("supported") else "NOT_PROMOTED"
    return result


# ---------------------------------------------------------------------------
# Exact v4 residual-memory/system decoders


def _pair_form(word: int) -> dict[str, Any] | None:
    """Decode the integer LDP/STP pair class, retaining invalid candidates.

    ``None`` means the word is not the integer pair class at all (notably
    SIMD/FP pair encodings).  An object with ``supported=False`` means that it
    is an integer pair-shaped word whose mode, width, or overlap is outside
    the deliberately tiny v4 admission set.  Keeping that distinction lets
    the analyzer publish a fail-closed family instead of silently dropping a
    selected 029 occurrence.
    """

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        raise ExtensionError("raw instruction word is not uint32")
    # bits 29:27 plus bit 25 identify the integer pair class.  SIMD/FP pair
    # forms carry 0x2c here and are intentionally outside this decoder.
    if (word & 0x3E000000) != 0x28000000:
        return None
    size = (word >> 30) & 0x3
    kind = "LDP" if word & 0x00400000 else "STP"
    mode_bits = (word >> 23) & 0x3
    mode_names = {1: "POST_INDEX", 2: "SIGNED_OFFSET", 3: "PRE_INDEX"}
    mode = mode_names.get(mode_bits)
    rt, rt2, rn = word & 0x1F, (word >> 10) & 0x1F, (word >> 5) & 0x1F
    if size == 0:
        width, width_bits, element_size = "W", 32, 4
    elif size == 2:
        width, width_bits, element_size = "X", 64, 8
    else:
        # size=1 is LDPSW; size=3 is reserved for this scalar pair class.
        width = "LDPSW" if size == 1 else "RESERVED"
        width_bits, element_size = (32, 4) if size == 1 else (None, None)
    byte_offset = sign_extend((word >> 15) & 0x7F, 7) * (element_size or 1)
    supported = True
    reasons: list[str] = []
    if size not in (0, 2):
        supported = False
        reasons.append("LDPSW or reserved pair width")
    if mode is None:
        supported = False
        reasons.append("reserved pair addressing mode")
    elif mode == "PRE_INDEX":
        supported = False
        reasons.append("pre-index pair form is outside exact v4 reach")
    elif mode == "POST_INDEX" and not (kind == "LDP" and size == 2):
        supported = False
        reasons.append("only reached LDP X post-index is admitted")
    if kind == "LDP" and rt == rt2:
        supported = False
        reasons.append("LDP destination overlap is constrained-unpredictable")
    # Encoding 31 is SP for Rn but ZR for Rt/Rt2.  It is therefore not an
    # overlap when the writeback base is SP; a non-31 base register matching a
    # destination is the constrained-unpredictable hazard.
    if mode == "POST_INDEX" and rn != 31 and rn in {rt, rt2}:
        supported = False
        reasons.append("post-index base/destination overlap is fail-closed")
    if not reasons:
        reason = "qualified reached integer pair form"
    else:
        reason = "; ".join(reasons)
    address_mode = "SIGNED_OFFSET" if mode == "SIGNED_OFFSET" else (mode or "UNKNOWN")
    result = {
        "family": PAIR_MEMORY,
        "operation": kind,
        "kind": kind,
        "width": width,
        "width_bits": width_bits,
        "element_size": element_size,
        "rt": rt,
        "rt2": rt2,
        "rn": rn,
        "first_register": rt,
        "second_register": rt2,
        "base_register": rn,
        "offset": byte_offset,
        "byte_offset": byte_offset,
        "address_mode": address_mode,
        "mode": mode,
        "writeback": mode == "POST_INDEX",
        "supported": supported,
        "valid": supported,
        "reason": reason,
    }
    if kind == "LDP":
        result.update({"first_destination": rt, "second_destination": rt2})
    else:
        result.update({"first_source_register": rt, "second_source_register": rt2})
    return result


def decode_pair(word: int) -> dict[str, Any] | None:
    """Return only source-gated, exact v4-admitted scalar pair forms."""

    if not _arm_source_available():
        return None
    info = _pair_form(word)
    return None if info is None or not info["supported"] else dict(info)


def _decode_pair(word: int) -> dict[str, Any] | None:
    """Compatibility-named strict decoder used by focused audits."""

    return decode_pair(word)


def _decode_ldp_signed_offset(word: int) -> dict[str, Any] | None:
    info = decode_pair(word)
    return None if info is None or info.get("operation") != "LDP" or info.get("address_mode") != "SIGNED_OFFSET" else info


def _decode_ldp_post_index(word: int) -> dict[str, Any] | None:
    info = decode_pair(word)
    return None if info is None or info.get("operation") != "LDP" or info.get("address_mode") != "POST_INDEX" else info


def _decode_stp_signed_offset(word: int) -> dict[str, Any] | None:
    info = decode_pair(word)
    return None if info is None or info.get("operation") != "STP" or info.get("address_mode") != "SIGNED_OFFSET" else info


def _sign_extending_form(word: int) -> dict[str, Any] | None:
    """Decode only LDRSW X and LDRSB W unsigned-immediate forms.

    The fixed top bits include the unsigned-immediate addressing mode.  A
    register-offset, unscaled, pre-index, post-index, LDRSB X, or other
    sign-extending variant therefore never reaches the supported path.
    """

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        raise ExtensionError("raw instruction word is not uint32")
    base = word & 0xFFC00000
    if base == 0xB9800000:
        family, operation, width, width_bits, element_size = SIGN_EXTENDING_MEMORY, "LDRSW", "X", 64, 4
        # LDRSW unsigned immediate has a 12-bit immediate scaled by four.
        immediate = (word >> 10) & 0xFFF
    elif base == 0x39C00000:
        family, operation, width, width_bits, element_size = SIGN_EXTENDING_MEMORY, "LDRSB", "W", 32, 1
        immediate = (word >> 10) & 0xFFF
    else:
        return None
    return {
        "family": family,
        "operation": operation,
        "width": width,
        "width_bits": width_bits,
        "element_size": element_size,
        "rt": word & 0x1F,
        "rd": word & 0x1F,
        "rn": (word >> 5) & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "destination_register": word & 0x1F,
        "destination_width": width,
        "extension_semantics": "SIGN_EXTEND_S32_TO_X64" if operation == "LDRSW" else "SIGN_EXTEND_S8_TO_W32_ZERO_UPPER_X",
        "offset": immediate * element_size,
        "byte_offset": immediate * element_size,
        "address_mode": "UNSIGNED_IMMEDIATE",
        "mode": "UNSIGNED",
        "writeback": False,
        "supported": True,
        "valid": True,
        "reason": "qualified reached sign-extending unsigned-immediate form",
    }


def evaluate_sign_extending(value: int, source_bits: int, destination_bits: int) -> int | None:
    """Evaluate the local signed-load transform with architectural masking."""

    if source_bits not in (8, 32) or destination_bits not in (32, 64) or source_bits > destination_bits:
        return None
    source_mask = (1 << source_bits) - 1
    destination_mask = (1 << destination_bits) - 1
    value &= source_mask
    signed = value - (1 << source_bits) if value & (1 << (source_bits - 1)) else value
    return signed & destination_mask


def evaluate_signed_load(value: int, source_bits: int, destination_bits: int) -> int | None:
    """Alias with an instruction-neutral name for signed-load unit tests."""

    return evaluate_sign_extending(value, source_bits, destination_bits)


def _is_sign_extending_candidate(word: int) -> bool:
    """Recognize scalar sign-extending load families for fail-closed output."""

    top = word & 0xFF000000
    # LDRSB W/X use the 0x38/0x39 scalar load class; LDRSW X uses 0xb8/0xb9.
    # The opcode subfields below exclude ordinary unsigned LDR byte/word forms
    # while retaining their unscaled/index/writeback siblings as unsupported.
    return top in {0x38000000, 0x39000000, 0xB8000000, 0xB9000000} and ((word >> 22) & 0x3) in {2, 3}


def decode_sign_extending(word: int) -> dict[str, Any] | None:
    """Public decoder for the two exact reached sign-extending forms."""

    if not _arm_source_available():
        return None
    info = _sign_extending_form(word)
    return None if info is None else dict(info)


def _decode_ldrsw_unsigned_immediate(word: int) -> dict[str, Any] | None:
    info = decode_sign_extending(word)
    return None if info is None or info.get("operation") != "LDRSW" else info


def _decode_ldrsb_unsigned_immediate(word: int) -> dict[str, Any] | None:
    info = decode_sign_extending(word)
    return None if info is None or info.get("operation") != "LDRSB" else info


def _system_form(word: int) -> dict[str, Any] | None:
    """Classify A64 system/control words, with one exact DAIFClr exception."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        raise ExtensionError("raw instruction word is not uint32")
    if (word & 0xFFC00000) != 0xD5000000:
        return None
    if word == 0xD50342FF:
        return {
            "family": SYSTEM_CONTROL,
            "operation": "DAIFClr",
            "mask": "IRQ",
            "supported": True,
            "valid": True,
            "reason": "exact DAIFClr IRQ/PSTATE-only side effect",
            "side_effect": "PSTATE_DAIF_IRQ_UNMASK",
            "writes_gpr": False,
            "writes_nzcv": False,
            "address_mode": "SYSTEM",
            "writeback": False,
        }
    return {
        "family": SYSTEM_CONTROL,
        "operation": "UNSUPPORTED_SYSTEM_FORM",
        "supported": False,
        "valid": False,
        "reason": "system/control form is outside exact v4 DAIFClr boundary",
        "writes_gpr": False,
        "writes_nzcv": False,
    }


def decode_system_control(word: int) -> dict[str, Any] | None:
    """Public source-gated decoder for exact DAIFClr only."""

    if not _arm_source_available():
        return None
    info = _system_form(word)
    return None if info is None or not info["supported"] else dict(info)


def _decode_system(word: int) -> dict[str, Any] | None:
    return decode_system_control(word)


def _classify_v4_word_impl(word: int, decoder: Any) -> dict[str, Any]:
    pair = _pair_form(word)
    if pair is not None:
        if pair["supported"]:
            result = dict(pair)
            result.update({"label": DECODER_EXTENSION_CANDIDATE, "supported": True})
            return result
        result = dict(pair)
        result.update({"label": UNKNOWN, "supported": False})
        return result
    sign_form = _sign_extending_form(word)
    if sign_form is not None:
        result = dict(sign_form)
        result.update({"label": DECODER_EXTENSION_CANDIDATE, "supported": True})
        return result
    if _is_sign_extending_candidate(word):
        return {"family": SIGN_EXTENDING_MEMORY, "label": UNKNOWN, "supported": False, "reason": "unseen sign-extending addressing/width variant remains fail-closed"}
    system = _system_form(word)
    if system is not None:
        result = dict(system)
        result["label"] = DECODER_EXTENSION_CANDIDATE if result.get("supported") else UNKNOWN
        return result
    result = _classify_v3_word_impl(word, decoder)
    return result


def classify_v4_word(word: int, decoder: Any) -> dict[str, Any]:
    """Apply the official-source gate to v4 residual forms and inherited 032."""

    result = _classify_v4_word_impl(word, decoder)
    if result.get("supported") and not _arm_source_available():
        result = dict(result)
        result["supported"] = False
        result["label"] = UNKNOWN
        result["reason"] = "official Arm primary source unavailable; form remains UNKNOWN and fail-closed"
        result["source_access_status"] = "UNKNOWN_SOURCE_UNAVAILABLE"
    else:
        result["source_access_status"] = "AVAILABLE_AND_HASH_PINNED" if result.get("supported") else "NOT_PROMOTED"
    return result


def _residual_memory_load_origin(decoder: Any, address: Any, *, va: int) -> Any:
    """Reuse only the inherited, exact DCB load provenance rule."""

    if getattr(address, "kind", None) in {"DCB_SECTION", "DCB_ARRAY"}:
        return decoder._memory_load_origin(address, 0, va=va)
    # A scalar/MC/base address does not identify DCB data in this transform.
    return decoder.UNKNOWN


def _residual_address_add(decoder: Any, address: Any, delta: int, *, va: int) -> Any:
    """Add a pair-lane/writeback delta with architectural modulo-64 rules."""

    if _is_constant(address):
        return decoder.constant((int(address.value) + int(delta)) & MASK64)
    if _is_address(address, decoder):
        return _address_add_modulo64(decoder, address, int(delta), va)
    return decoder.UNKNOWN


def _origin_description(value: Any) -> str:
    return value.describe() if hasattr(value, "describe") else "UNKNOWN"


def _classify_v2_word_impl(word: int, decoder: Any) -> dict[str, Any]:
    """Classify one word under the qualified v2 frontier boundary.

    The result explicitly distinguishes a form that v2 can model from an
    encoding-mask match that remains fail-closed.  This function makes no
    reachability claim.
    """

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        raise ExtensionError("raw instruction word is not uint32")
    shifted = _decode_shifted_logical(word)
    if shifted is not None:
        family, valid, width, shift_kind, amount, rm, rn, rd = shifted
        if valid and family == "AND_SHIFT":
            return {"family": family, "label": DECODER_EXTENSION_CANDIDATE, "supported": True, "reason": "qualified AND shifted-register semantics", "width": width, "shift_type": shift_kind, "shift_amount": amount, "rn": rn, "rm": rm, "rd": rd}
        if valid and family == "ANDS_SHIFT" and rd == 31:
            return {"family": family, "label": FLAG_ONLY_NO_GPR_DEF, "supported": True, "reason": "TST alias writes NZCV only", "width": width, "shift_type": shift_kind, "shift_amount": amount, "rn": rn, "rm": rm, "rd": rd}
        return {"family": family, "label": DECODER_EXTENSION_CANDIDATE if valid else UNKNOWN, "supported": False, "reason": "BIC/EOR/other logical shifted form remains fail-closed" if valid else "invalid logical shifted width/amount", "width": width, "shift_type": shift_kind, "shift_amount": amount, "rn": rn, "rm": rm, "rd": rd}
    logical_imm = _decode_logical_immediate(word, decoder)
    if logical_imm is not None:
        family, valid, width, rd, rn, _imm = logical_imm
        if valid and family == "ANDS_IMM" and rd == 31:
            return {"family": family, "label": FLAG_ONLY_NO_GPR_DEF, "supported": True, "reason": "TST alias writes NZCV only", "width": width, "rn": rn, "rd": rd}
        if valid and family == "ANDS_IMM":
            return {"family": family, "label": TAINT_KILL_REQUIRED, "supported": True, "reason": "destination-local kill for flag-setting logical scalar", "width": width, "rn": rn, "rd": rd}
        return {"family": family, "label": DECODER_EXTENSION_CANDIDATE if valid else UNKNOWN, "supported": False, "reason": "logical immediate remains outside v2 scalar frontier" if valid else "reserved logical immediate encoding", "width": width, "rn": rn, "rd": rd}
    add_imm = _decode_add_sub_immediate(word)
    if add_imm is not None:
        family, valid, width, s, rd, rn, imm, op = add_imm
        if not valid:
            return {"family": family, "label": UNKNOWN, "supported": False, "reason": "reserved or tagged add/sub immediate encoding", "width": width, "rd": rd, "rn": rn}
        if s and rd == 31:
            return {"family": "ADDS_SUBS_IMM_FLAG", "label": FLAG_ONLY_NO_GPR_DEF, "supported": True, "reason": "CMP/CMN alias writes NZCV only", "width": width, "rd": rd, "rn": rn, "immediate": imm}
        if rd == 31:
            return {"family": "ADD_SUB_IMM_SP", "label": TAINT_KILL_REQUIRED, "supported": True, "reason": "destination-local SP kill; no GPR definition", "width": width, "rd": rd, "rn": rn, "immediate": imm}
        return {"family": "ADDS_SUBS_IMM" if s else "ADD_SUB_IMM", "label": TAINT_KILL_REQUIRED, "supported": True, "reason": "destination-local conservative scalar kill", "width": width, "rd": rd, "rn": rn, "immediate": imm}
    add_reg = _decode_add_sub_register(word)
    if add_reg is not None:
        family, valid, width, s, rd, rn, rm, field, amount, op = add_reg
        if not valid:
            return {"family": family, "label": UNKNOWN, "supported": False, "reason": "reserved add/sub register encoding", "width": width, "rd": rd, "rn": rn, "rm": rm}
        if s and rd == 31:
            return {"family": "ADDS_SUBS_EXT_FLAG" if family == "ADD_SUB_EXT" else "ADDS_SUBS_REG_FLAG", "label": FLAG_ONLY_NO_GPR_DEF, "supported": True, "reason": "CMP/CMN alias writes NZCV only", "width": width, "rd": rd, "rn": rn, "rm": rm, "shift_or_option": field, "shift_amount": amount}
        if rd == 31:
            # Shifted/extended register forms encode ZR as Rd=31.  Only the
            # immediate form has SP as an architectural destination.
            if family == "ADD_SUB_REG":
                return {"family": "ADD_SUB_REG_ZR_DISCARD", "label": UNKNOWN, "supported": False, "reason": "S=0 shifted-register Rd=ZR is retained as an unqualified discard form", "width": width, "rd": rd, "rn": rn, "rm": rm}
            return {"family": "ADD_SUB_EXT_SP" if family == "ADD_SUB_EXT" else "ADD_SUB_REG_ZR_DISCARD", "label": UNKNOWN, "supported": False, "reason": "extended-register Rd=ZR/SP-adjacent form remains unqualified and fail-closed", "width": width, "rd": rd, "rn": rn, "rm": rm}
        return {"family": "ADDS_SUBS_EXT" if family == "ADD_SUB_EXT" else "ADDS_SUBS_REG", "label": TAINT_KILL_REQUIRED, "supported": True, "reason": "destination-local conservative scalar kill", "width": width, "rd": rd, "rn": rn, "rm": rm, "shift_or_option": field, "shift_amount": amount}
    ccmp = _decode_ccmp(word)
    if ccmp is not None:
        family, valid, width, rn, rm, cond = ccmp
        return {"family": family, "label": FLAG_ONLY_NO_GPR_DEF, "supported": valid, "reason": "conditional compare writes NZCV only", "width": width, "rn": rn, "rm": rm, "condition": cond}
    bitfield = _decode_bitfield(word)
    if bitfield is not None:
        family, valid, width, n, opc, immr, imms, rn, rd = bitfield
        return {"family": "BITFIELD_IMM" if valid else family, "operation": family, "label": DECODER_EXTENSION_CANDIDATE if valid else UNKNOWN, "supported": valid, "reason": "qualified SBFM/BFM/UBFM semantics" if valid else "invalid bitfield N/sf/opc/imm combination", "width": width, "n": n, "opc": opc, "immr": immr, "imms": imms, "rn": rn, "rd": rd}
    variable = _decode_variable_shift(word)
    if variable is not None:
        family, _valid, rd, rn = variable
        return {"family": "VARIABLE_SHIFT", "label": TAINT_KILL_REQUIRED, "supported": True, "reason": "destination-local conservative kill for variable shift", "rd": rd, "rn": rn}
    divide = _decode_divide(word)
    if divide is not None:
        family, _valid, rd = divide
        return {"family": "DIVIDE", "label": TAINT_KILL_REQUIRED, "supported": True, "reason": "destination-local conservative kill for divide", "rd": rd}
    csel = _decode_csel(word)
    if csel is not None:
        family, _valid, rd, rn, rm = csel
        return {"family": family, "label": TAINT_KILL_REQUIRED, "supported": True, "reason": "destination-local conservative kill for conditional select", "rd": rd, "rn": rn, "rm": rm}
    # The remaining 029 classes are intentionally not extended here.
    return {"family": "UNKNOWN_FORM", "label": UNKNOWN, "supported": False, "reason": "no qualified v2 scalar form"}


def _arm_source_available() -> bool:
    return (
        ARM_PRIMARY_SOURCE.get("access_status") == "AVAILABLE_AND_HASH_PINNED"
        and bool(ARM_PRIMARY_SOURCE.get("canonical_url"))
        and ARM_PRIMARY_SOURCE.get("document_identifier") == "DDI0602 (ID092025)"
    )


def classify_v2_word(word: int, decoder: Any) -> dict[str, Any]:
    """Apply the official-source gate before promoting a scalar form."""

    result = _classify_v2_word_impl(word, decoder)
    if result.get("supported") and not _arm_source_available():
        result = dict(result)
        result["supported"] = False
        result["label"] = UNKNOWN
        result["reason"] = "official Arm primary source unavailable; form remains UNKNOWN and fail-closed"
        result["source_access_status"] = "UNKNOWN_SOURCE_UNAVAILABLE"
    else:
        result["source_access_status"] = "AVAILABLE_AND_HASH_PINNED" if result.get("supported") else "NOT_PROMOTED"
    return result


def _decoder_recognizes_027(decoder: Any, word: int, va: int) -> bool:
    """Mirror 027 dispatch so v2 only consumes its unsupported frontier."""

    if decoder.decode_bl_target(word, va) is not None:
        return True
    if decoder.is_blr(word) is not None or decoder.is_br(word) is not None or decoder.is_ret(word):
        return True
    if decoder.decode_b_target(word, va) is not None:
        return True
    if decoder.adr_target(word, va) is not None or decoder.adrp_target(word, va) is not None:
        return True
    for function in (decoder.is_movz, decoder.is_movk, decoder.is_movn, decoder.is_orr_imm, decoder.is_and_imm, decoder.is_orr_reg, decoder.is_add_sub_imm, decoder.is_add_sub_reg, decoder.is_add_sub_ext):
        if function(word) is not None:
            return True
    if decoder._decode_mem(word) is not None or decoder.is_atomic_or_exclusive(word) or decoder._is_nop(word):
        return True
    return False


def _direct_control_family(word: int) -> str | None:
    """Name only the direct A64 control encodings repaired in v2."""

    if (word & 0x7C000000) == 0x14000000:
        return "B"
    if (word & 0xFF000010) == 0x54000000:
        return "B.cond"
    if (word & 0x7E000000) == 0x34000000:
        return "CBZ_CBNZ"
    if (word & 0x7E000000) == 0x36000000:
        return "TBZ_TBNZ"
    return None


def _decode_bit_masks(n: int, imms: int, immr: int, width: int) -> tuple[int, int] | None:
    combined = (n << 6) | ((~imms) & 0x3F)
    if combined == 0:
        return None
    length = combined.bit_length() - 1
    if length < 1 or (1 << length) > width:
        return None
    levels = (1 << length) - 1
    s, r = imms & levels, immr & levels
    esize = 1 << length
    d = (s - r) & levels
    welem = (1 << (s + 1)) - 1
    telem = (1 << (d + 1)) - 1
    rotated = _shift_value(welem, esize, 3, r)
    if rotated is None:
        return None
    wmask = 0
    tmask = 0
    for offset in range(0, width, esize):
        wmask |= rotated << offset
        tmask |= telem << offset
    return wmask & ((1 << width) - 1), tmask & ((1 << width) - 1)


def decode_and_shift(word: int) -> dict[str, Any] | None:
    """Public pure decoder for the qualified AND (shifted register) form."""

    if not _arm_source_available():
        return None
    info = _decode_shifted_logical(word)
    if info is None or info[0] != "AND_SHIFT" or not info[1]:
        return None
    family, valid, width, shift_type, shift_amount, rm, rn, rd = info
    return {"family": family, "width": width, "shift_type": shift_type, "shift_amount": shift_amount, "rm": rm, "rn": rn, "rd": rd}


def decode_bitfield(word: int) -> dict[str, Any] | None:
    """Public pure decoder for valid SBFM/BFM/UBFM immediate forms."""

    if not _arm_source_available():
        return None
    info = _decode_bitfield(word)
    if info is None or not info[1]:
        return None
    family, _valid, width, n, opc, immr, imms, rn, rd = info
    return {"family": "BITFIELD_IMM", "operation": family, "width": width, "n": n, "opc": opc, "immr": immr, "imms": imms, "rn": rn, "rd": rd}


def evaluate_and_shift(left: int, right: int, width: int, shift_type: int, shift_amount: int) -> int | None:
    """Evaluate a qualified AND shifted-register operation on constants."""

    if width not in (32, 64):
        return None
    shifted = _shift_value(right, width, shift_type, shift_amount)
    return None if shifted is None else (left & shifted) & ((1 << width) - 1)


def evaluate_eor_shift(left: int, right: int, width: int, shift_type: int, shift_amount: int) -> int | None:
    """Evaluate EOR (shifted register) modulo the selected operand width."""

    if width not in (32, 64):
        return None
    shifted = _shift_value(right, width, shift_type, shift_amount)
    return None if shifted is None else (left ^ shifted) & ((1 << width) - 1)


def evaluate_bic_shift(left: int, right: int, width: int, shift_type: int, shift_amount: int) -> int | None:
    """Evaluate BIC (shifted register) modulo the selected operand width."""

    if width not in (32, 64):
        return None
    shifted = _shift_value(right, width, shift_type, shift_amount)
    return None if shifted is None else (left & ~shifted) & ((1 << width) - 1)


def evaluate_three_source(left: int, right: int, accumulator: int, width: int, operation: str) -> int | None:
    """Evaluate MADD or UMADDL with architectural modulo-width semantics."""

    if operation == "MADD" and width in (32, 64):
        mask = (1 << width) - 1
        return ((left & mask) * (right & mask) + (accumulator & mask)) & mask
    if operation == "UMADDL" and width == 64:
        return (((left & 0xFFFFFFFF) * (right & 0xFFFFFFFF)) + (accumulator & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    return None


def evaluate_madd(left: int, right: int, accumulator: int, width: int) -> int | None:
    return evaluate_three_source(left, right, accumulator, width, "MADD")


def evaluate_umaddl(left: int, right: int, accumulator: int) -> int | None:
    return evaluate_three_source(left, right, accumulator, 64, "UMADDL")


def evaluate_bitfield(src: int, dst: int, width: int, opc: int, n: int, immr: int, imms: int) -> int | None:
    """Evaluate official BFM/SBFM/UBFM pseudocode on constant operands."""

    if width not in (32, 64) or opc not in (0, 1, 2) or n != (1 if width == 64 else 0) or not (0 <= immr < width and 0 <= imms < width):
        return None
    masks = _decode_bit_masks(n, imms, immr, width)
    if masks is None:
        return None
    wmask, tmask = masks
    mask = (1 << width) - 1
    src &= mask; dst &= mask
    rotated = _shift_value(src, width, 3, immr)
    if rotated is None:
        return None
    bot = rotated & wmask
    if opc == 1:  # BFM
        return ((dst & ~tmask) | (((dst & ~wmask) | bot) & tmask)) & mask
    if opc == 2:  # UBFM
        return bot & tmask
    sign = (src >> imms) & 1
    top = mask if sign else 0
    return ((top & ~tmask) | (bot & tmask)) & mask


def _origin_reg(state: "V2State", reg: int, *, sp_allowed: bool = False, zr_zero: bool = True, decoder: Any | None = None) -> Any:
    if reg == 31:
        if sp_allowed:
            return _normalize_address_origin(state.sp, decoder)
        return decoder.constant(0) if zr_zero and decoder is not None else None
    value = state.regs.get(reg, decoder.UNKNOWN if decoder is not None else None)
    return _normalize_address_origin(value, decoder)


def _set_reg(state: "V2State", reg: int, origin: Any, decoder: Any) -> None:
    if reg == 31:
        return
    state.regs[reg] = _normalize_address_origin(origin, decoder)


def _set_sp(state: "V2State", origin: Any, decoder: Any) -> None:
    state.sp = _normalize_address_origin(origin, decoder)


def _is_constant(value: Any) -> bool:
    return getattr(value, "kind", None) == "CONSTANT" and getattr(value, "value", None) is not None


def _is_address(value: Any, decoder: Any) -> bool:
    return getattr(value, "kind", None) in getattr(decoder, "ADDRESS_ORIGIN_KINDS", frozenset())


def _normalize_address_origin(value: Any, decoder: Any) -> Any:
    """Keep every address-origin offset canonical modulo 2^64.

    The inherited scalar decoder can construct an address origin by adding a
    constant without applying an architectural width mask.  Experiment 032
    therefore makes the modulo-2^64 rule a state invariant at every register
    and SP boundary, not merely in the newly-qualified arithmetic evaluator.
    Non-address values and address origins whose offset is already unknown
    are preserved unchanged.
    """

    if not _is_address(value, decoder):
        return value
    offset = getattr(value, "offset", None)
    if offset is None:
        return value
    canonical = int(offset) & MASK64
    if canonical == offset:
        return value
    return replace(value, offset=canonical)


def _same(a: Any, b: Any) -> bool:
    return a == b


def _bitfield_origin(decoder: Any, state: "V2State", info: Mapping[str, Any], va: int) -> Any:
    width = int(info["width"])
    mask = (1 << width) - 1
    rn, rd = int(info["rn"]), int(info["rd"])
    # ``classify_v2_word`` normalizes every valid encoding to the
    # ``BITFIELD_IMM`` frontier family.  Keep the architectural operation
    # separately so BFM can consume old-Rd bits and UBFM/SBFM can apply their
    # distinct top-mask behavior during analyzer-side constant propagation.
    operation = str(info.get("operation") or {0: "SBFM", 1: "BFM", 2: "UBFM"}.get(int(info.get("opc", 3)), ""))
    src = _origin_reg(state, rn, zr_zero=True, decoder=decoder)
    dst = _origin_reg(state, rd, zr_zero=True, decoder=decoder)
    if not _is_constant(src) or (operation == "BFM" and not _is_constant(dst)):
        # An exact full-width move is the only non-constant provenance
        # identity we retain.  Partial bitfield transforms are not pointer or
        # DCB-data identities in this lattice.
        if width == 64 and info["immr"] == 0 and info["imms"] == width - 1 and operation in {"SBFM", "BFM", "UBFM"}:
            return _normalize_address_origin(src, decoder)
        return decoder.UNKNOWN
    src_value = int(src.value) & mask
    if operation == "BFM" and not _is_constant(dst):
        return decoder.UNKNOWN
    dst_value = int(dst.value) & mask if _is_constant(dst) else 0
    opc = {"SBFM": 0, "BFM": 1, "UBFM": 2}.get(operation)
    result = evaluate_bitfield(src_value, dst_value, width, int(opc) if opc is not None else 3, int(info["n"]), int(info["immr"]), int(info["imms"]))
    return decoder.UNKNOWN if result is None else decoder.constant(result & mask)


def _logical_shift_origin(decoder: Any, state: "V2State", info: Mapping[str, Any], va: int) -> Any:
    """Conservatively propagate an exact EOR/BIC result or identity."""

    width = int(info["width"])
    left = _origin_reg(state, int(info["rn"]), zr_zero=True, decoder=decoder)
    right = _origin_reg(state, int(info["rm"]), zr_zero=True, decoder=decoder)
    shift_type, shift_amount = int(info["shift_type"]), int(info["shift_amount"])
    mask = (1 << width) - 1
    shifted_right = None
    if _is_constant(right):
        shifted_right = _shift_value(int(right.value), width, shift_type, shift_amount)

    # Constant evaluation is exact for both widths and takes precedence over
    # provenance identities.  W-register results remain constants only; a W
    # write can never preserve an X-width address/DCB origin.
    if _is_constant(left) and shifted_right is not None:
        if info["family"] == "EOR_SHIFT":
            evaluated = evaluate_eor_shift(int(left.value), int(right.value), width, shift_type, shift_amount)
        else:
            evaluated = evaluate_bic_shift(int(left.value), int(right.value), width, shift_type, shift_amount)
        return decoder.UNKNOWN if evaluated is None else decoder.constant(evaluated)
    if width != 64:
        return decoder.UNKNOWN

    identity_shift = shift_type == 0 and shift_amount == 0
    if info["family"] == "EOR_SHIFT":
        # XOR by zero is an exact identity; zero XOR an unshifted address is
        # also an exact identity.  Equal unshifted origins cancel to zero.
        if shifted_right == 0:
            return _normalize_address_origin(left, decoder) if _is_address(left, decoder) else decoder.UNKNOWN
        if _is_constant(left) and int(left.value) == 0 and identity_shift:
            return _normalize_address_origin(right, decoder) if _is_address(right, decoder) else decoder.UNKNOWN
        if identity_shift and _is_address(left, decoder) and left == right:
            return decoder.constant(0)
        return decoder.UNKNOWN

    # BIC is AND with the inverted shifted operand.  BIC by zero is an exact
    # identity, while a zero left operand or all-ones mask is exact zero.
    if shifted_right == 0:
        return _normalize_address_origin(left, decoder) if _is_address(left, decoder) else decoder.UNKNOWN
    if _is_constant(left) and int(left.value) == 0:
        return decoder.constant(0)
    if shifted_right == mask:
        return decoder.constant(0)
    if identity_shift and _is_address(left, decoder) and left == right:
        return decoder.constant(0)
    return decoder.UNKNOWN


def _known_three_source_product(left: Any, right: Any, operation: str) -> tuple[bool, int]:
    """Return (known, product) while recognizing a proven zero product."""

    left_value = int(left.value) if _is_constant(left) else None
    right_value = int(right.value) if _is_constant(right) else None
    if operation == "UMADDL":
        if left_value is not None:
            left_value &= 0xFFFFFFFF
        if right_value is not None:
            right_value &= 0xFFFFFFFF
        mask = 0xFFFFFFFFFFFFFFFF
    else:
        mask = 0xFFFFFFFFFFFFFFFF
    if left_value == 0 or right_value == 0:
        return True, 0
    if left_value is None or right_value is None:
        return False, 0
    return True, (left_value * right_value) & mask


def _address_add_modulo64(decoder: Any, address: Any, delta: int, source_va: int) -> Any:
    """Add an exact constant to an address origin modulo 2^64."""

    if not _is_address(address, decoder) or getattr(address, "offset", None) is None:
        return decoder.UNKNOWN
    canonical = _normalize_address_origin(address, decoder)
    wrapped = (int(canonical.offset) + (int(delta) & MASK64)) & MASK64
    return _normalize_address_origin(replace(canonical, offset=wrapped, source_va=source_va), decoder)


def _three_source_origin(decoder: Any, state: "V2State", info: Mapping[str, Any], va: int) -> Any:
    """Propagate only exact MADD/UMADDL constants and address identities."""

    operation = str(info["operation"])
    width = int(info["width"])
    left = _origin_reg(state, int(info["rn"]), zr_zero=True, decoder=decoder)
    right = _origin_reg(state, int(info["rm"]), zr_zero=True, decoder=decoder)
    accumulator = _origin_reg(state, int(info["ra"]), zr_zero=True, decoder=decoder)
    product_known, product = _known_three_source_product(left, right, operation)
    if product_known and _is_constant(accumulator):
        value = evaluate_three_source(
            int(left.value) if _is_constant(left) else 0,
            int(right.value) if _is_constant(right) else 0,
            int(accumulator.value),
            width,
            operation,
        )
        # A proven zero factor makes the product zero even if the other factor
        # is unknown; in that case the accumulator alone is the result.
        if value is None:
            value = (int(accumulator.value) + product) & ((1 << width) - 1)
        return decoder.constant(value)
    if product_known and product == 0:
        if width == 64 and _is_address(accumulator, decoder):
            return _normalize_address_origin(accumulator, decoder)
        return decoder.UNKNOWN
    if product_known and width == 64 and _is_address(accumulator, decoder):
        # The only non-constant address arithmetic admitted here is an address
        # accumulator plus an exactly known product.
        if accumulator.offset is None:
            return decoder.UNKNOWN
        return _address_add_modulo64(decoder, accumulator, product, va)

    # Exact identity extensions: coefficient one and zero accumulator preserve
    # an address multiplier.  This is still under the same 64-bit-only rule.
    if operation == "MADD" and width == 64 and _is_constant(accumulator) and int(accumulator.value) == 0:
        if _is_constant(left) and int(left.value) == 1 and _is_address(right, decoder):
            return _normalize_address_origin(right, decoder)
        if _is_constant(right) and int(right.value) == 1 and _is_address(left, decoder):
            return _normalize_address_origin(left, decoder)
    return decoder.UNKNOWN


@dataclass
class V2State:
    regs: dict[int, Any]
    sp: Any
    flags_unknown: bool = False
    blocked: bool = False
    unsupported: set[str] | None = None
    handled_forms: list[dict[str, Any]] | None = None
    taint_kills: list[dict[str, Any]] | None = None

    def clone(self) -> "V2State":
        return V2State(dict(self.regs), self.sp, self.flags_unknown, self.blocked, set(self.unsupported or ()), list(self.handled_forms or ()), list(self.taint_kills or ()))


def _merge_states(old: V2State | None, new: V2State, unknown: Any) -> V2State:
    if old is None:
        return new.clone()
    merged: dict[int, Any] = {}
    for reg in set(old.regs) | set(new.regs):
        if reg in old.regs and reg in new.regs and _same(old.regs[reg], new.regs[reg]):
            merged[reg] = old.regs[reg]
    # Join differing SP origins to UNKNOWN; choosing either path would make a
    # loop merge unsound and could manufacture an address provenance.
    sp = old.sp if _same(old.sp, new.sp) else unknown
    return V2State(merged, sp, old.flags_unknown or new.flags_unknown, old.blocked or new.blocked, set(old.unsupported or ()) | set(new.unsupported or ()), list(old.handled_forms or ()) + [x for x in new.handled_forms or () if x not in old.handled_forms], list(old.taint_kills or ()) + [x for x in new.taint_kills or () if x not in old.taint_kills])


def _range_bounds(site: Mapping[str, Any]) -> tuple[int, int, int]:
    # 027 public rows wrap the dependency site under ``site``.  Falling back
    # to the store word would silently turn a full loop into a one-word scan.
    source = site.get("site") if isinstance(site.get("site"), Mapping) else site
    try:
        store = parse_hex(site["store_va"], "site store")
        start = parse_hex(source.get("loop_head_va", source.get("add_va", site["store_va"])), "site start")
        end = parse_hex(source.get("back_edge_va", source.get("store_va")), "site end") + 4
    except (KeyError, TypeError) as exc:
        raise ExtensionError("site range shape is malformed") from exc
    if start % 4 or (end - 4) % 4 or store % 4 or start > end - 4 or not start <= store < end:
        raise ExtensionError("site range is not aligned/ordered")
    return start, end, store


def analyze_bounded_site_v2(
    decoder: Any,
    image: Any,
    site: Mapping[str, Any],
    *,
    seed_origins: Mapping[int, Any] | None = None,
    seed_sp: Any | None = None,
    max_states: int = 512,
    classifier: Any | None = None,
) -> dict[str, Any]:
    """Analyze one exact 027 site with the qualified v2 scalar frontier."""

    classifier = classify_v2_word if classifier is None else classifier
    head, end_exclusive, store_va = _range_bounds(site)
    end_edge = end_exclusive - 4
    addresses = list(range(head, end_edge + 4, 4))
    if store_va not in addresses:
        addresses.append(store_va)
        addresses.sort()
    allowed = set(addresses)
    initial = {reg: _normalize_address_origin(decoder.argument(reg), decoder) for reg in range(8)}
    if seed_origins:
        initial.update({reg: _normalize_address_origin(origin, decoder) for reg, origin in seed_origins.items()})
    initial_sp = _normalize_address_origin(seed_sp, decoder) if seed_sp is not None else decoder.UNKNOWN
    states: dict[int, V2State] = {head: V2State(initial, initial_sp, False, False, set(), [], [])}
    queue = [head]
    visited = 0
    observations: list[dict[str, Any]] = []
    unsupported_reasons: set[str] = set()
    handled_forms: list[dict[str, Any]] = []
    control_events: list[dict[str, Any]] = []
    taint_kills: list[dict[str, Any]] = []
    blocker_events: list[dict[str, Any]] = []
    direct_calls: list[dict[str, Any]] = []
    branch_edges: list[dict[str, Any]] = []
    system_side_effects: list[dict[str, Any]] = []

    def get_origin(reg: int, *, sp_allowed: bool = False) -> Any:
        if reg == 31:
            return _normalize_address_origin(state.sp, decoder) if sp_allowed else decoder.constant(0)
        return _normalize_address_origin(state.regs.get(reg, decoder.UNKNOWN), decoder)

    while queue and visited < max_states:
        va = queue.pop(0)
        state = states[va].clone()
        visited += 1
        word = image.word(va)
        if word is None:
            state.blocked = True
            state.unsupported.add("UNMAPPED_WORD")
            unsupported_reasons.add("UNMAPPED_WORD")
            continue
        next_addresses: list[int] = []
        direct_bl = decoder.decode_bl_target(word, va)
        if direct_bl is not None:
            direct_calls.append({"va": fmt(va), "target": fmt(direct_bl), "arguments": {f"X{r}": state.regs[r].describe() for r in range(8) if r in state.regs}})
            state.regs.clear()
            state.sp = decoder.UNKNOWN
            next_addresses = [va + 4]
        elif decoder.is_blr(word) is not None or decoder.is_br(word) is not None:
            state.blocked = True
            reason = "INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS"
            state.unsupported.add(reason)
            unsupported_reasons.add(reason)
            blocker_events.append({"va": fmt(va), "word": fmt(word), "raw_word": fmt(word), "family": reason, "effect": "FAIL_CLOSED", "reason": "indirect branch target is unresolved"})
            branch_edges.append({"va": fmt(va), "kind": "BLR" if decoder.is_blr(word) is not None else "BR", "target": "UNKNOWN"})
        elif decoder.is_ret(word):
            # RET has no register definition and terminates the bounded CFG;
            # model it as a known control edge rather than allowing the
            # scalar fallback to classify the encoding as unknown.
            next_addresses = []
        else:
            branch = decoder.decode_b_target(word, va)
            if branch is not None:
                next_addresses.append(branch)
                if (word & 0x7C000000) != 0x14000000:
                    next_addresses.append(va + 4)
                branch_edges.append({"va": fmt(va), "kind": _direct_control_family(word) or "DIRECT_BRANCH", "target": fmt(branch), "repair_id": "DIRECT_CONTROL_DISPATCH_REPAIR"})
            else:
                next_addresses = [va + 4]

            # First give the newly-qualified scalar forms a chance to consume
            # the raw word.  A valid but intentionally unsupported family is
            # an explicit fail-closed boundary.
            # Existing 027 decoder forms retain their frozen semantics.  The
            # v2 extension is consulted only for words that 027 itself
            # classified as unsupported in this bounded site.
            if branch is not None or decoder.is_ret(word):
                v2 = {"family": "DIRECT_CONTROL_DISPATCH_REPAIR", "supported": True, "label": "CONTROL_FLOW_CONSERVATIVE", "reason": "DIRECT_CONTROL_DISPATCH_REPAIR: direct branch/return is modeled with conservative path splitting", "control_family": _direct_control_family(word) or "RET"}
            else:
                v2 = classifier(word, decoder) if not _decoder_recognizes_027(decoder, word, va) else {"family": "027_RECOGNIZED", "supported": False, "label": "027_RECOGNIZED", "reason": "frozen 027 decoder path"}
            handled = bool(v2.get("supported"))
            if handled:
                family = v2["family"]
                if v2["label"] == FLAG_ONLY_NO_GPR_DEF:
                    effect = "NZCV_ONLY_NO_GPR_DEF"
                elif family == "AND_SHIFT":
                    effect = "AND_SHIFT_RESULT_OR_ZR_DISCARD"
                elif family == "BITFIELD_IMM":
                    effect = "BITFIELD_RESULT_OR_ZR_DISCARD"
                elif family in {"THREE_SOURCE_UNVALIDATED", "EOR_SHIFT", "BIC_SHIFT"}:
                    effect = "ARITHMETIC_RESULT_OR_ZR_DISCARD"
                elif family == PAIR_MEMORY:
                    effect = "PAIR_LOAD_PRESTATE_DEFINITION" if v2.get("operation") == "LDP" else "PAIR_STORE_TWO_LANES"
                elif family == SIGN_EXTENDING_MEMORY:
                    effect = "SIGN_EXTENDING_LOAD_DESTINATION_LOCAL"
                elif family == SYSTEM_CONTROL:
                    effect = "SYSTEM_SIDE_EFFECT_ONLY"
                elif v2["label"] == TAINT_KILL_REQUIRED:
                    effect = "DESTINATION_LOCAL_KILL"
                else:
                    effect = "DIRECT_CONTROL_DISPATCH_REPAIR"
                handled_record = {"va": fmt(va), "word": fmt(word), "raw_word": fmt(word), "family": family, "label": v2["label"], "effect": effect, "reason": v2["reason"], "source_provenance": "ARM_PRIMARY_SOURCE_DDI0602_ID092025_2025-09"}
                if family in ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES:
                    for field in ("operation", "width", "rn", "rm", "ra", "rd", "shift_type", "shift_amount", "selector"):
                        if field in v2:
                            handled_record[field] = v2[field]
                if family in {PAIR_MEMORY, SIGN_EXTENDING_MEMORY}:
                    for field in ("operation", "width", "width_bits", "element_size", "rn", "rm", "ra", "rd", "rt", "rt2", "base_register", "first_register", "second_register", "first_destination", "second_destination", "first_source_register", "second_source_register", "destination_register", "destination_width", "extension_semantics", "offset", "byte_offset", "address_mode", "mode", "writeback"):
                        if field in v2:
                            handled_record[field] = v2[field]
                if family == SYSTEM_CONTROL:
                    for field in ("operation", "mask", "side_effect", "writes_gpr", "writes_nzcv", "address_mode", "writeback"):
                        if field in v2:
                            handled_record[field] = v2[field]
                if family == "DIRECT_CONTROL_DISPATCH_REPAIR":
                    handled_record["control_family"] = v2.get("control_family", "UNKNOWN_DIRECT_CONTROL")
                    handled_record["repair_id"] = "DIRECT_CONTROL_DISPATCH_REPAIR"
                    control_events.append(handled_record)
                else:
                    handled_forms.append(handled_record)
                if v2["label"] == FLAG_ONLY_NO_GPR_DEF:
                    state.flags_unknown = True
                elif family == "AND_SHIFT":
                    width = int(v2["width"])
                    left = get_origin(int(v2["rn"]), sp_allowed=False)
                    right = get_origin(int(v2["rm"]), sp_allowed=False)
                    result: Any = decoder.UNKNOWN
                    if getattr(left, "kind", None) == "CONSTANT" and getattr(right, "kind", None) == "CONSTANT":
                        evaluated = evaluate_and_shift(int(left.value), int(right.value), width, int(v2["shift_type"]), int(v2["shift_amount"]))
                        if evaluated is not None:
                            result = decoder.constant(evaluated)
                    elif getattr(left, "kind", None) == "CONSTANT" and int(left.value) == 0:
                        result = decoder.constant(0)
                    elif width == 64 and int(v2["rn"]) == int(v2["rm"]) and int(v2["shift_type"]) == 0 and int(v2["shift_amount"]) == 0:
                        result = left
                    if int(v2["rd"]) != 31:
                        _set_reg(state, int(v2["rd"]), result, decoder)
                elif family == "BITFIELD_IMM":
                    if int(v2["rd"]) != 31:
                        _set_reg(state, int(v2["rd"]), _bitfield_origin(decoder, state, v2, va), decoder)
                elif family in {"THREE_SOURCE_UNVALIDATED", "EOR_SHIFT", "BIC_SHIFT"}:
                    if family == "THREE_SOURCE_UNVALIDATED":
                        result = _three_source_origin(decoder, state, v2, va)
                    else:
                        result = _logical_shift_origin(decoder, state, v2, va)
                    handled_forms[-1]["result_origin"] = result.describe() if hasattr(result, "describe") else "UNKNOWN"
                    handled_forms[-1]["result_kind"] = getattr(result, "kind", "UNKNOWN")
                    handled_forms[-1]["destination"] = "ZR" if int(v2["rd"]) == 31 else f"X{int(v2['rd'])}"
                    if int(v2["rd"]) != 31:
                        _set_reg(state, int(v2["rd"]), result, decoder)
                elif family == PAIR_MEMORY:
                    # Both pair lanes read the same pre-state base.  Compute
                    # all origins before defining either destination so a
                    # destination/base overlap can never manufacture a
                    # post-writeback address.  The decoder has already
                    # rejected constrained-unpredictable overlaps.
                    rn = int(v2["rn"])
                    rt = int(v2["rt"])
                    rt2 = int(v2["rt2"])
                    offset = int(v2["offset"])
                    element_size = int(v2["element_size"])
                    base = get_origin(rn, sp_allowed=True)
                    # Post-index loads access the pre-state base and the next
                    # lane; their signed immediate is writeback-only.  A
                    # signed-offset load/store applies the immediate to both
                    # lane addresses.  This distinction is architectural and
                    # is covered by an end-to-end post-index regression test.
                    lane0_target = base if v2.get("address_mode") == "POST_INDEX" else _residual_address_add(decoder, base, offset, va=va)
                    lane1_target = _residual_address_add(decoder, lane0_target, element_size, va=va)
                    lane_targets = (lane0_target, lane1_target)
                    if v2.get("operation") == "LDP":
                        lane0_origin = _residual_memory_load_origin(decoder, lane0_target, va=va)
                        lane1_origin = _residual_memory_load_origin(decoder, lane1_target, va=va)
                        lane_results = []
                        for lane, destination, origin, lane_target in ((0, rt, lane0_origin, lane0_target), (1, rt2, lane1_origin, lane1_target)):
                            lane_results.append({"pair_lane": lane, "destination_register": destination, "destination": "ZR" if destination == 31 else f"{v2['width']}{destination}", "origin": _origin_description(origin), "origin_kind": getattr(origin, "kind", "UNKNOWN"), "effective_address": _origin_description(lane_target), "effective_address_kind": getattr(lane_target, "kind", "UNKNOWN"), "effective_address_offset": getattr(lane_target, "offset", None)})
                            if destination != 31:
                                _set_reg(state, destination, origin, decoder)
                        handled_forms[-1]["pair_lane_results"] = lane_results
                        handled_forms[-1]["pair_lanes"] = lane_results
                        handled_forms[-1]["pair_lane_count"] = 2
                        handled_forms[-1]["load_base_origin"] = _origin_description(base)
                        handled_forms[-1]["load_base_kind"] = getattr(base, "kind", "UNKNOWN")
                        if v2.get("writeback"):
                            writeback = _residual_address_add(decoder, base, offset, va=va)
                            handled_forms[-1]["writeback_register"] = "SP" if rn == 31 else f"X{rn}"
                            handled_forms[-1]["writeback_origin"] = _origin_description(writeback)
                            handled_forms[-1]["writeback_kind"] = getattr(writeback, "kind", "UNKNOWN")
                            if rn == 31:
                                _set_sp(state, writeback, decoder)
                            else:
                                _set_reg(state, rn, writeback, decoder)
                    else:
                        # STP is an observation at both element addresses;
                        # retain source identities even when either address is
                        # unknown.  No exact reached STP has writeback.
                        source0 = get_origin(rt, sp_allowed=False)
                        source1 = get_origin(rt2, sp_allowed=False)
                        for lane, target, source, source_register in ((0, lane_targets[0], source0, rt), (1, lane_targets[1], source1, rt2)):
                            lane_offset = offset + lane * element_size
                            observations.append({"va": fmt(va), "word": fmt(word), "raw_word": fmt(word), "kind": "STP", "operation": "STP", "width": v2["width"], "width_bits": v2["width_bits"], "element_size": element_size, "target": target, "form": v2["address_mode"], "address_mode": v2["address_mode"], "writeback": False, "base_register": rn, "rt": rt, "rt2": rt2, "first_register": rt, "second_register": rt2, "offset": lane_offset, "instruction_offset": offset, "pair_offset": lane_offset, "source_register": source_register, "source": source, "pair_lane": lane, "pair_lane_offset": lane_offset})
                        handled_forms[-1]["pair_lanes"] = [
                            {"pair_lane": 0, "offset": offset, "source_register": rt, "source_origin": _origin_description(source0)},
                            {"pair_lane": 1, "offset": offset + element_size, "source_register": rt2, "source_origin": _origin_description(source1)},
                        ]
                        handled_forms[-1]["pair_lane_count"] = 2
                        handled_forms[-1]["writeback_register"] = None
                        handled_forms[-1]["writeback_origin"] = None
                elif family == SIGN_EXTENDING_MEMORY:
                    rn = int(v2["rn"])
                    rt = int(v2["rt"])
                    base = get_origin(rn, sp_allowed=True)
                    target = _residual_address_add(decoder, base, int(v2["offset"]), va=va)
                    result = _residual_memory_load_origin(decoder, target, va=va)
                    if rt != 31:
                        _set_reg(state, rt, result, decoder)
                    handled_forms[-1]["destination"] = "ZR" if rt == 31 else f"X{rt}" if v2["width"] == "X" else f"W{rt}"
                    handled_forms[-1]["result_origin"] = _origin_description(result)
                    handled_forms[-1]["result_kind"] = getattr(result, "kind", "UNKNOWN")
                    handled_forms[-1]["effective_address"] = _origin_description(target)
                    handled_forms[-1]["effective_address_kind"] = getattr(target, "kind", "UNKNOWN")
                elif family == SYSTEM_CONTROL:
                    # DAIFClr affects PSTATE.DAIF only.  It defines no GPR or
                    # NZCV state; record the side-effect boundary explicitly.
                    side_effect = dict(handled_record)
                    side_effect["side_effect_boundary"] = v2.get("side_effect", "UNKNOWN")
                    side_effect["gpr_definition"] = "NONE"
                    side_effect["nzcv_definition"] = "NONE"
                    system_side_effects.append(side_effect)
                elif v2["label"] == TAINT_KILL_REQUIRED:
                    rd = int(v2.get("rd", 31))
                    if v2["family"] == "ADD_SUB_IMM_SP" and rd == 31:
                        _set_sp(state, decoder.UNKNOWN, decoder)
                    elif rd != 31:
                        state.regs.pop(rd, None)
                    kill_record = {"va": fmt(va), "word": fmt(word), "raw_word": fmt(word), "family": v2["family"], "destination": "SP" if rd == 31 and v2["family"] == "ADD_SUB_IMM_SP" else ("ZR" if rd == 31 else f"X{rd}"), "reason": v2["reason"]}
                    state.taint_kills.append(kill_record)
                    taint_kills.append(kill_record)
                    if v2["family"].startswith("ADDS") or v2["family"] in {"ANDS_IMM"}:
                        state.flags_unknown = True
            else:
                # Existing 027 forms retain their exact behavior.  We copy
                # only the small dispatch needed for this v2 pass; no global
                # monkey patching or decoder mutation is used.
                adr = decoder.adr_target(word, va)
                adrp = decoder.adrp_target(word, va)
                if adr is not None:
                    _set_reg(state, adr[1], decoder.constant(adr[0]), decoder)
                elif adrp is not None:
                    _set_reg(state, adrp[1], decoder.constant(adrp[0]), decoder)
                else:
                    movz, movk, movn = decoder.is_movz(word), decoder.is_movk(word), decoder.is_movn(word)
                    logical_imm = decoder.is_orr_imm(word)
                    and_imm_027 = decoder.is_and_imm(word)
                    logical = decoder.is_orr_reg(word)
                    add_imm_027 = decoder.is_add_sub_imm(word)
                    add_reg_027 = decoder.is_add_sub_reg(word)
                    add_ext_027 = decoder.is_add_sub_ext(word)
                    if movz is not None:
                        width, imm, hw, rd = movz
                        if width == "W" and hw > 1:
                            _set_reg(state, rd, decoder.UNKNOWN, decoder)
                        else:
                            _set_reg(state, rd, decoder.constant((imm << (16 * hw)) & (0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF)), decoder)
                    elif movn is not None:
                        width, imm, hw, rd = movn
                        if width == "W" and hw > 1:
                            _set_reg(state, rd, decoder.UNKNOWN, decoder)
                        else:
                            mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                            _set_reg(state, rd, decoder.constant((~(imm << (16 * hw))) & mask), decoder)
                    elif movk is not None:
                        width, imm, hw, rd = movk
                        old = state.regs.get(rd)
                        if old is None or not _is_constant(old) or (width == "W" and hw > 1):
                            _set_reg(state, rd, decoder.UNKNOWN, decoder)
                        else:
                            mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                            half = 0xFFFF << (16 * hw)
                            _set_reg(state, rd, decoder.constant(((old.value & ~half) | (imm << (16 * hw))) & mask), decoder)
                    elif logical_imm is not None:
                        width, rd, rn, imm = logical_imm
                        source = decoder.constant(0) if rn == 31 else state.regs.get(rn, decoder.UNKNOWN)
                        result = decoder.constant((source.value | imm) & (0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF)) if _is_constant(source) else decoder.UNKNOWN
                        _set_reg(state, rd, result, decoder)
                    elif and_imm_027 is not None:
                        width, rd, rn, imm = and_imm_027
                        source = state.regs.get(rn, decoder.UNKNOWN)
                        result = decoder.constant(source.value & imm) if _is_constant(source) else decoder.UNKNOWN
                        _set_reg(state, rd, result, decoder)
                    elif logical is not None:
                        width, rd, rn, rm, shift_kind, amount = logical
                        left = decoder.constant(0) if rn == 31 else state.regs.get(rn, decoder.UNKNOWN)
                        right = state.regs.get(rm, decoder.UNKNOWN)
                        # Keep the frozen 027 ORR decoder's supported shift
                        # subset exactly; the v2 ROR extension applies only
                        # to AND_SHIFT.
                        shifted = decoder.shift_value(int(right.value), width, shift_kind, amount) if _is_constant(right) else None
                        if _is_constant(left) and shifted is not None:
                            result = decoder.constant((left.value | shifted) & (0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF))
                        elif rn == 31 and getattr(right, "kind", None) in {"BASE", "MC_BASE", "SHRM_BASE", "DCB_SECTION", "DCB_ARRAY", "DCB_DATA"} and ((width == "X" and shift_kind == 0 and amount == 0) or (getattr(right, "kind", None) == "DCB_DATA" and shift_kind == 0 and amount == 0)):
                            result = right
                        else:
                            result = decoder.UNKNOWN
                        _set_reg(state, rd, result, decoder)
                    elif add_imm_027 is not None:
                        op, width, imm, rn, rd = add_imm_027
                        left = state.sp if rn == 31 else state.regs.get(rn, decoder.UNKNOWN)
                        result = decoder._combine_add(left, decoder.constant(imm), subtract=op == "SUB", source_va=va)
                        if width == "W" and getattr(left, "kind", None) in decoder.ADDRESS_ORIGIN_KINDS:
                            result = decoder.UNKNOWN
                        if width == "W" and _is_constant(result):
                            result = decoder.constant(result.value & 0xFFFFFFFF)
                        result = decoder._classify_address_origin(result, store_va)
                        if rd == 31:
                            _set_sp(state, result, decoder)
                        else:
                            _set_reg(state, rd, result, decoder)
                    elif add_reg_027 is not None or add_ext_027 is not None:
                        decoded = add_reg_027 if add_reg_027 is not None else add_ext_027
                        op, width, rd, rn, rm, field, amount = decoded
                        # Shifted-register ADD/SUB uses ZR for Rn=31; only the
                        # extended-register encoding admits SP as Rn=31.
                        if add_ext_027 is not None:
                            left = state.sp if rn == 31 else state.regs.get(rn, decoder.UNKNOWN)
                        else:
                            left = decoder.constant(0) if rn == 31 else state.regs.get(rn, decoder.UNKNOWN)
                        right = state.regs.get(rm, decoder.UNKNOWN)
                        if add_ext_027 is not None and _is_constant(right):
                            extended = decoder.extend_value(right.value, field)
                            right = decoder.UNKNOWN if extended is None else decoder.constant(extended << amount)
                        elif add_reg_027 is not None and _is_constant(right):
                            shifted = decoder.shift_value(right.value, width, field, amount)
                            right = decoder.UNKNOWN if shifted is None else decoder.constant(shifted)
                        elif add_reg_027 is not None and getattr(right, "kind", None) in decoder.ADDRESS_ORIGIN_KINDS and field == 0:
                            right = replace(right, offset=None if right.offset is None else right.offset << amount)
                        else:
                            right = decoder.UNKNOWN
                        result = decoder._combine_add(left, right, subtract=op == "SUB", source_va=va)
                        if width == "W" and getattr(left, "kind", None) in decoder.ADDRESS_ORIGIN_KINDS:
                            result = decoder.UNKNOWN
                        if width == "W" and _is_constant(result):
                            result = decoder.constant(result.value & 0xFFFFFFFF)
                        result = decoder._classify_address_origin(result, store_va)
                        _set_reg(state, rd, result, decoder)
                    else:
                        mem = decoder._decode_mem(word)
                        if mem is not None:
                            kind, width, rn, index_or_rt, offset, scale, form = mem
                            base = state.sp if rn == 31 else state.regs.get(rn, decoder.UNKNOWN)
                            is_load = kind == "LDR"
                            if form.startswith("REGISTER_OFFSET:"):
                                rt = int(form.split(":", 1)[1])
                                index_register = index_or_rt if index_or_rt is not None else 31
                                index = decoder.constant(0) if index_register == 31 else state.regs.get(index_register, decoder.UNKNOWN)
                                transformed = None
                                if _is_constant(index):
                                    extended = decoder.extend_value(index.value, offset)
                                    transformed = None if extended is None else extended << scale
                                target = decoder._combine_add(base, decoder.constant(transformed), source_va=va) if transformed is not None else (replace(base, offset=None, source_va=va) if getattr(base, "kind", None) in decoder.ADDRESS_ORIGIN_KINDS else decoder.UNKNOWN)
                                if is_load:
                                    _set_reg(state, rt, decoder._memory_load_origin(target, 0, va=va), decoder)
                                else:
                                    observations.append({"va": fmt(va), "word": fmt(word), "kind": "STR", "width": width, "target": target, "form": "REGISTER_OFFSET", "base_register": rn, "index_register": index_or_rt, "index_option": offset, "index_scale": scale, "source_register": rt, "source": state.regs.get(rt, decoder.UNKNOWN)})
                            else:
                                rt = index_or_rt if index_or_rt is not None else 31
                                effective_base = decoder._with_offset(base, offset, source_va=va) if form == "PREINDEX" else base
                                if is_load:
                                    _set_reg(state, rt, decoder._memory_load_origin(effective_base, 0, va=va), decoder)
                                else:
                                    observations.append({"va": fmt(va), "word": fmt(word), "kind": "STR", "width": width, "target": effective_base, "form": form, "base_register": rn, "offset": offset, "source_register": rt, "source": state.regs.get(rt, decoder.UNKNOWN)})
                                if form in {"POSTINDEX", "PREINDEX"}:
                                    writeback = decoder._with_offset(base, offset, source_va=va)
                                    if is_load and rt == rn:
                                        writeback = decoder.UNKNOWN
                                    if rn == 31:
                                        _set_sp(state, writeback, decoder)
                                    else:
                                        _set_reg(state, rn, writeback, decoder)
                        elif decoder.is_atomic_or_exclusive(word):
                            reason = "EXCLUSIVE_AND_LSE_ATOMICS_UNSUPPORTED"
                            state.blocked = True; state.unsupported.add(reason); unsupported_reasons.add(reason)
                            blocker_events.append({"va": fmt(va), "word": fmt(word), "raw_word": fmt(word), "family": reason, "effect": "FAIL_CLOSED", "reason": "atomic/exclusive memory semantics are outside v2"})
                        elif decoder._is_nop(word):
                            pass
                        else:
                            info = classifier(word, decoder)
                            reason = f"UNSUPPORTED_V2_{info.get('family', 'UNKNOWN_FORM')}"
                            # Match 027's fail-closed unrecognized-instruction
                            # boundary: no stale register/SP provenance may
                            # cross an unsupported v2 form.
                            state.regs.clear()
                            state.sp = decoder.UNKNOWN
                            state.blocked = True; state.unsupported.add(reason); unsupported_reasons.add(reason)
                            blocker_events.append({"va": fmt(va), "word": fmt(word), "raw_word": fmt(word), "family": info.get("family", "UNKNOWN_FORM"), "label": info.get("label", UNKNOWN), "effect": "FAIL_CLOSED", "reason": info.get("reason", "unsupported v2 form")})

        # Decorate all observations emitted at this VA with serializable
        # origins.  The source remains explicit even when target is unknown.
        for observation in observations:
            if observation.get("va") != fmt(va) or "target_origin" in observation:
                continue
            target = observation.get("target")
            if not hasattr(target, "kind"):
                continue
            observation["state_blocked"] = state.blocked
            observation["unsupported"] = sorted(state.unsupported or ())
            observation["target_origin"] = target.describe()
            observation["target_kind"] = target.kind
            observation["target_base"] = target.base
            observation["target_offset"] = target.offset
            observation["source_origin"] = observation.get("source").describe() if hasattr(observation.get("source"), "describe") else "UNKNOWN"
            source = observation.get("source")
            observation["source_kind"] = getattr(source, "kind", "UNKNOWN")
            observation["source_section"] = getattr(source, "section", None)
            observation.pop("target", None); observation.pop("source", None)
            observation["site_va"] = fmt(store_va)
            observation["symbolic_base_plus_offset"] = target.kind in getattr(decoder, "ADDRESS_ORIGIN_KINDS", frozenset())
            observation["flags_state"] = "UNKNOWN" if state.flags_unknown else "UNTOUCHED"

        for nxt in next_addresses:
            if nxt not in allowed:
                continue
            merged = _merge_states(states.get(nxt), state, decoder.UNKNOWN)
            if nxt not in states:
                states[nxt] = merged; queue.append(nxt)
            elif merged.regs != states[nxt].regs or merged.sp != states[nxt].sp or merged.blocked != states[nxt].blocked or merged.unsupported != states[nxt].unsupported or merged.flags_unknown != states[nxt].flags_unknown:
                states[nxt] = merged; queue.append(nxt)

    cfg_complete = not queue
    if not cfg_complete:
        unsupported_reasons.add("CFG_STATE_LIMIT_REACHED")
    # Ordinary single-register observations remain keyed by VA.  Pair stores
    # deliberately use (VA,lane), otherwise two architectural stores at one
    # instruction would be merged and one lane would disappear from the
    # evidence.
    by_va: dict[tuple[str, Any], dict[str, Any]] = {}
    for row in observations:
        row_key = (row["va"], row.get("pair_lane") if row.get("kind") == "STP" else None)
        old = by_va.get(row_key)
        if old is None:
            by_va[row_key] = row
        else:
            old["state_blocked"] = bool(old.get("state_blocked") or row.get("state_blocked"))
            old["unsupported"] = sorted(set(old.get("unsupported", ())) | set(row.get("unsupported", ())))
            for key in ("target_origin", "target_kind", "target_base", "target_offset", "source_origin", "source_kind", "source_section"):
                if old.get(key) != row.get(key):
                    old[key] = "UNKNOWN" if key in {"target_origin", "target_kind", "source_origin", "source_kind"} else None
    if unsupported_reasons:
        for row in by_va.values():
            row["state_blocked"] = True
    usable = [row for row in by_va.values() if not row.get("state_blocked")]
    labels: set[str] = set()
    for row in usable:
        if row.get("kind") in {"STR", "STP"} and row.get("source_kind") == "DCB_DATA":
            labels.add("DCB_CONSUMER_PATH")
        if row.get("target_kind") in {"MC_BASE", "SHRM_BASE"}:
            labels.add("MC_OR_SHRM_SYMBOLIC_TARGET")
    if unsupported_reasons:
        labels = {INDIRECT}
    elif not usable:
        labels = {"NO_TARGET_WITHIN_MODEL"}
    elif not labels:
        labels = {"NO_TARGET_WITHIN_MODEL"}
    def dedup(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[tuple[Any, ...], dict[str, Any]] = {}
        for row in rows:
            key = (row.get("va"), row.get("raw_word", row.get("word")), row.get("family"), row.get("label"), row.get("reason"), row.get("destination"))
            unique[key] = dict(row)
        return sorted(unique.values(), key=lambda row: (row.get("va", ""), row.get("raw_word", row.get("word", "")), row.get("family", ""), row.get("destination", "")))

    handled_forms = dedup(handled_forms)
    control_events = dedup(control_events)
    taint_kills = dedup(taint_kills)
    blocker_events = dedup(blocker_events)
    system_side_effects = dedup(system_side_effects)
    return {
        "site": {k: site[k] for k in sorted(site)},
        "store_va": fmt(store_va),
        "range": {"start": fmt(head), "end_exclusive": fmt(end_edge + 4), "size": end_edge + 4 - head},
        "discriminators": sorted(labels),
        "status": "SUPPORTED" if labels & {"DCB_CONSUMER_PATH", "MC_OR_SHRM_SYMBOLIC_TARGET"} else "UNKNOWN",
        "current_destination": "UNKNOWN",
        "target_observations": sorted(by_va.values(), key=lambda row: (row["va"], row.get("pair_lane", -1))),
        "usable_target_observations": sorted(usable, key=lambda row: row["va"]),
        "unsupported_forms": sorted(unsupported_reasons),
        "direct_calls": sorted(direct_calls, key=lambda row: row["va"]),
        "branch_edges": sorted(branch_edges, key=lambda row: row["va"]),
        "cfg_states_visited": visited,
        "cfg_state_limit": max_states,
        "cfg_complete": cfg_complete,
        "writer_absence": "UNKNOWN",
        "v2_handled_forms": handled_forms,
        "control_flow_events": control_events,
        "taint_kills": taint_kills,
        "reached_blocker_events": blocker_events,
        "system_side_effects": system_side_effects,
        "flags_model": {"writes_gpr": False, "control_conservative": True, "state": "UNKNOWN" if any(row.get("label") == FLAG_ONLY_NO_GPR_DEF for row in handled_forms) else "UNTOUCHED"},
    }


def _analyze_site_bound_v3_legacy(image: Any, decoder: Any, site: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
    """Run the explicit v3 hook architecture with all state local to a call."""

    return analyze_bounded_site_v3(decoder, image, site, **kwargs)


def analyze_bounded_site_v3(
    decoder: Any,
    image: Any,
    site: Mapping[str, Any],
    *,
    seed_origins: Mapping[int, Any] | None = None,
    seed_sp: Any | None = None,
    max_states: int = 512,
) -> dict[str, Any]:
    """Explicit local v3 fork: 031 dataflow plus qualified arithmetic hooks."""

    result = analyze_bounded_site_v2(
        decoder,
        image,
        site,
        seed_origins=seed_origins,
        seed_sp=seed_sp,
        max_states=max_states,
        classifier=classify_v3_word,
    )
    # Keep the 031 event key for structural compatibility while publishing a
    # v3-named view for consumers that need to distinguish this extension.
    result["v3_handled_forms"] = [dict(event) for event in result["v2_handled_forms"]]
    arithmetic = [event for event in result["v3_handled_forms"] if event.get("family") in ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES]
    result["v3_syntactic_frontier"] = {
        "families": sorted({str(event["family"]) for event in arithmetic}),
        "occurrence_count": len(arithmetic),
    }
    return result


def analyze_bounded_site_v4(
    decoder: Any,
    image: Any,
    site: Mapping[str, Any],
    *,
    seed_origins: Mapping[int, Any] | None = None,
    seed_sp: Any | None = None,
    max_states: int = 512,
) -> dict[str, Any]:
    """Run 032's bounded dataflow with only the exact v4 residual hooks."""

    result = analyze_bounded_site_v2(
        decoder,
        image,
        site,
        seed_origins=seed_origins,
        seed_sp=seed_sp,
        max_states=max_states,
        classifier=classify_v4_word,
    )
    result["v4_handled_forms"] = [dict(event) for event in result["v2_handled_forms"]]
    result["v4_syntactic_frontier"] = {
        "families": sorted({str(event["family"]) for event in result["v4_handled_forms"]}),
        "occurrence_count": len(result["v4_handled_forms"]),
    }
    return result


def analyze_site_bound(image: Any, decoder: Any, site: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
    """Public v4 bounded-site entry point; all state remains call-local."""

    return analyze_bounded_site_v4(decoder, image, site, **kwargs)


# ---------------------------------------------------------------------------
# Exact 71-site analysis and publication


def _site_frontier_rows(manifest_029: Mapping[str, Any]) -> dict[int, list[Mapping[str, Any]]]:
    result: dict[int, list[Mapping[str, Any]]] = {}
    for row in manifest_029["frontier"]["occurrences"]:
        result.setdefault(int(row["site_index"]), []).append(row)
    return result


def _all_range_forms_selected(manifest_029: Mapping[str, Any]) -> dict[str, Any]:
    by_site = _site_frontier_rows(manifest_029)
    eligible: list[int] = []
    for index, rows in sorted(by_site.items()):
        families = {str(row["classification"].get("family")) for row in rows}
        if families and families <= PREDICTED_IMPLEMENTED_FAMILIES:
            eligible.append(index)
    return {"all_range_forms_selected_site_count": len(eligible), "total_fail_closed_sites": 71, "ratio": f"{len(eligible)}/71", "site_indices": eligible, "basis": "syntactic membership only; neither CFG reachability nor closure prediction; v4 selects the complete 029 frontier family set, while exact form support and reached events are measured separately"}


INTERNAL_TO_029_FAMILY = {"CSEL": "CONDITIONAL_SELECT"}


def _event_raw_word(event: Mapping[str, Any]) -> str:
    """Read the public raw-word identity, with a compatibility fallback."""

    raw_word = event.get("raw_word", event.get("word"))
    if not isinstance(raw_word, str):
        raise ExtensionError("reached event raw word is malformed")
    return raw_word


def _selected_029_admission_lookup(manifest_029: Mapping[str, Any]) -> dict[tuple[int, str, str], dict[str, str]]:
    """Return the exact selected 029 occurrence identity keyed by site/VA/word."""

    lookup: dict[tuple[int, str, str], dict[str, str]] = {}
    for occurrence in manifest_029["frontier"]["occurrences"]:
        classification = occurrence["classification"]
        family = str(classification["family"])
        if family not in PREDICTED_IMPLEMENTED_FAMILIES:
            continue
        key = (int(occurrence["site_index"]), str(occurrence["va"]), str(occurrence["raw_word"]))
        value = {"family": family, "label": str(classification["label"])}
        if key in lookup and lookup[key] != value:
            raise ExtensionError(f"Experiment 029 selected occurrence identity is inconsistent: {key}")
        lookup[key] = value
    if len(lookup) != 352:
        raise ExtensionError("Experiment 029 selected admission cardinality changed")
    return lookup


def _admit_reached_extension_events(events: Sequence[Mapping[str, Any]], lookup: Mapping[tuple[int, str, str], Mapping[str, str]]) -> dict[str, int]:
    """Enforce exact 029 family/label admission for every reached event."""

    outside = family_mismatch = label_mismatch = 0
    for event in events:
        key = (int(event["site_index"]), str(event["va"]), _event_raw_word(event))
        admitted = lookup.get(key)
        if admitted is None:
            outside += 1
            raise ExtensionError(f"reached v4 extension event is outside selected 029 frontier: {key}")
        internal_family = str(event["family"])
        mapped_family = INTERNAL_TO_029_FAMILY.get(internal_family, internal_family)
        if mapped_family != admitted["family"]:
            family_mismatch += 1
            raise ExtensionError(f"reached v4 family mismatch at {key}: {mapped_family} != {admitted['family']}")
        # 029 intentionally classified arithmetic/residual rows as UNKNOWN
        # or CONTROL_OR_MEMORY_UNSUPPORTED before primary-source review.  A
        # v4 event may therefore carry a newly-qualified decoder label while
        # newly-qualified decoder label while retaining the exact original
        # frontier label in ``admission_label``/``frontier_label``.  Other
        # family/label changes remain hard failures.
        label_compatible = (
            str(event["label"]) == admitted["label"]
            or (
                mapped_family in ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES
                and admitted["label"] == UNKNOWN
                and str(event["label"]) == DECODER_EXTENSION_CANDIDATE
            )
            or (
                mapped_family in RESIDUAL_MEMORY_PREDICTED_FAMILIES
                and admitted["label"] == CONTROL_OR_MEMORY_UNSUPPORTED
                and str(event["label"]) == DECODER_EXTENSION_CANDIDATE
            )
        )
        if not label_compatible:
            label_mismatch += 1
            raise ExtensionError(f"reached v4 label mismatch at {key}: {event['label']} != {admitted['label']}")
        if mapped_family != internal_family:
            event["decoder_family"] = internal_family
            event["family"] = mapped_family
        event["admission_status"] = "PASS_EXACT_029_SELECTED"
        event["admission_family"] = admitted["family"]
        event["admission_label"] = admitted["label"]
        if str(event["label"]) != admitted["label"]:
            event["frontier_label"] = admitted["label"]
    return {"events_outside_selected": outside, "family_mismatch_count": family_mismatch, "label_mismatch_count": label_mismatch}


def _canonical_records(records: Sequence[Mapping[str, Any]]) -> list[str]:
    """Canonical full-record JSON used for inherited equality gates."""

    return sorted(json.dumps(dict(record), sort_keys=True, separators=(",", ":")) for record in records)


def _assert_inherited_equivalence(
    expected: Sequence[Mapping[str, Any]],
    actual: Sequence[Mapping[str, Any]],
    label: str,
    dependency: str,
) -> dict[str, Any]:
    expected_canonical = _canonical_records(expected)
    actual_canonical = _canonical_records(actual)
    if expected_canonical != actual_canonical:
        raise ExtensionError(f"inherited {dependency} {label} full-record equivalence mismatch")
    expected_bytes = ("\n".join(expected_canonical) + "\n").encode()
    actual_bytes = ("\n".join(actual_canonical) + "\n").encode()
    return {
        "expected_count": len(expected),
        "actual_count": len(actual),
        "exact_full_record_equality": True,
        "expected_canonical_sha256": sha256(expected_bytes),
        "actual_canonical_sha256": sha256(actual_bytes),
    }


def assert_inherited_031_equivalence(
    expected: Sequence[Mapping[str, Any]],
    actual: Sequence[Mapping[str, Any]],
    label: str,
) -> dict[str, Any]:
    """Require exact count and canonical full-record equality for 031 data."""

    return _assert_inherited_equivalence(expected, actual, label, "031")


def assert_inherited_032_equivalence(
    expected: Sequence[Mapping[str, Any]],
    actual: Sequence[Mapping[str, Any]],
    label: str,
) -> dict[str, Any]:
    """Require exact full-record equality against the frozen 032 result."""

    return _assert_inherited_equivalence(expected, actual, label, "032")


EXPECTED_031_TO_032_TRANSITIONS = {
    "031_NO_TARGET_WITHIN_MODEL_TO_032_NO_TARGET_WITHIN_MODEL": 51,
    "031_INDIRECT_OR_UNSUPPORTED_TO_032_INDIRECT_OR_UNSUPPORTED": 16,
    "031_INDIRECT_OR_UNSUPPORTED_TO_032_NO_TARGET_WITHIN_MODEL": 4,
    "031_NO_TARGET_WITHIN_MODEL_TO_032_INDIRECT_OR_UNSUPPORTED": 0,
}


def validate_031_to_032_transition_quadrants(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate the exact 031→032 four-quadrant transition ledger."""

    observed = Counter(str(row.get("delta_vs_031", {}).get("transition")) for row in results)
    expected = Counter(EXPECTED_031_TO_032_TRANSITIONS)
    counts = Counter({key: observed.get(key, 0) for key in expected})
    if set(observed) - set(expected) or counts != expected:
        raise ExtensionError(f"031->032 transition quadrant mismatch: {dict(observed)}")
    regression_key = "031_NO_TARGET_WITHIN_MODEL_TO_032_INDIRECT_OR_UNSUPPORTED"
    return {
        "counts": dict(sorted(counts.items())),
        "expected_counts": dict(sorted(expected.items())),
        "identity_check": counts == expected,
        "regression_count": counts.get(regression_key, 0),
        "regression_free": counts.get(regression_key, 0) == 0,
    }


EXPECTED_032_TO_033_TRANSITIONS = {
    "032_NO_TARGET_WITHIN_MODEL_TO_033_NO_TARGET_WITHIN_MODEL": 55,
    "032_INDIRECT_OR_UNSUPPORTED_TO_033_INDIRECT_OR_UNSUPPORTED": 1,
    "032_INDIRECT_OR_UNSUPPORTED_TO_033_NO_TARGET_WITHIN_MODEL": 15,
    "032_NO_TARGET_WITHIN_MODEL_TO_033_INDIRECT_OR_UNSUPPORTED": 0,
}


def validate_032_to_033_transition_quadrants(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate the measured 032→033 four-quadrant transition ledger."""

    observed = Counter(str(row.get("delta_vs_032", {}).get("transition")) for row in results)
    expected = Counter(EXPECTED_032_TO_033_TRANSITIONS)
    counts = Counter({key: observed.get(key, 0) for key in expected})
    if set(observed) - set(expected) or counts != expected:
        raise ExtensionError(f"032->033 transition quadrant mismatch: {dict(observed)}")
    regression_key = "032_NO_TARGET_WITHIN_MODEL_TO_033_INDIRECT_OR_UNSUPPORTED"
    return {
        "counts": dict(sorted(counts.items())),
        "expected_counts": dict(sorted(expected.items())),
        "identity_check": counts == expected,
        "regression_count": counts.get(regression_key, 0),
        "regression_free": counts.get(regression_key, 0) == 0,
    }


def analyze_exact_sites(decoder: Any, manifest_032: Mapping[str, Any], manifest_029: Mapping[str, Any], firmware: bytes) -> dict[str, Any]:
    if len(firmware) != XBL_SIZE or sha256(firmware) != XBL_SHA256:
        raise ExtensionError("exact XBL input mismatch")
    _validate_032_manifest(manifest_032); _validate_029_manifest(manifest_029)
    image = decoder.Image(firmware)
    # The committed 032 result embeds the exact 027 site row under ``site``;
    # use that frozen range identity while retaining the 032 top-level row for
    # the per-site transition ledger.
    rows = []
    baseline_032_by_store: dict[str, Mapping[str, Any]] = {}
    for row in manifest_032["sites"]:
        if not isinstance(row, Mapping) or not isinstance(row.get("site"), Mapping):
            raise ExtensionError("Experiment 032 embedded site row is malformed")
        baseline_032_by_store[str(row["store_va"])] = row
        embedded = row["site"]
        if INDIRECT in embedded.get("discriminators", []):
            rows.append(embedded)
    if len(rows) != 71:
        raise ExtensionError("exact 71-site scope changed")
    frontier_by_site = _site_frontier_rows(manifest_029)
    frontier_by_key = {(int(item["site_index"]), item["va"]): item for item in manifest_029["frontier"]["occurrences"]}
    admission_lookup = _selected_029_admission_lookup(manifest_029)
    results: list[dict[str, Any]] = []
    for index, site in enumerate(rows):
        # The 029 index is the stable row identity for its 71-site scan.  It
        # must remain present; no inferred or reordered site is accepted.
        candidate_index = next((int(r["site_index"]) for r in manifest_029["site_ranges"] if r["store_va"] == site["store_va"]), None)
        if candidate_index is None:
            raise ExtensionError(f"027/029 site identity mismatch at {site['store_va']}")
        result = analyze_site_bound(image, decoder, site)
        result["site_index"] = candidate_index
        for event in result["v2_handled_forms"]:
            event["site_index"] = candidate_index
        result["v4_handled_forms"] = result["v2_handled_forms"]
        for event in result["control_flow_events"]:
            event["site_index"] = candidate_index
        for event in result["taint_kills"]:
            event["site_index"] = candidate_index
        for event in result["system_side_effects"]:
            event["site_index"] = candidate_index
        for event in result["reached_blocker_events"]:
            event["site_index"] = candidate_index
            source = frontier_by_key.get((candidate_index, event["va"]))
            if source is not None:
                event["family"] = source["classification"]["family"]
                event["frontier_label"] = source["classification"]["label"]
                event["frontier_reason"] = source["classification"]["reason"]
        selected = _all_range_forms_selected(manifest_029)
        frontier_shape = {
            "occurrence_count": len(frontier_by_site.get(candidate_index, [])),
            "families": sorted({row["classification"]["family"] for row in frontier_by_site.get(candidate_index, [])}),
            "labels": sorted({row["classification"]["label"] for row in frontier_by_site.get(candidate_index, [])}),
            "all_range_forms_selected": candidate_index in selected["site_indices"],
        }
        result["v2_syntactic_frontier"] = dict(frontier_shape)
        result["v3_syntactic_frontier"] = dict(frontier_shape)
        result["v4_syntactic_frontier"] = dict(frontier_shape)
        still_fail_closed = INDIRECT in result["discriminators"]
        result["delta_vs_027"] = {"was_fail_closed": True, "is_fail_closed": still_fail_closed, "transitioned_to_no_target_within_v4_model": not still_fail_closed, "transitioned_to_no_target_within_v3_model": not still_fail_closed, "transition": "027_INDIRECT_OR_UNSUPPORTED_TO_033_INDIRECT_OR_UNSUPPORTED" if still_fail_closed else "027_INDIRECT_OR_UNSUPPORTED_TO_033_NO_TARGET_WITHIN_MODEL", "baseline_discriminators": list(site["discriminators"])}
        baseline = baseline_032_by_store.get(str(site["store_va"]))
        if baseline is None:
            raise ExtensionError(f"032 site identity mismatch at {site['store_va']}")
        baseline_discriminators = list(baseline.get("discriminators", []))
        baseline_fail_closed = INDIRECT in baseline_discriminators
        baseline_state = "INDIRECT_OR_UNSUPPORTED" if baseline_fail_closed else "NO_TARGET_WITHIN_MODEL"
        current_state = "INDIRECT_OR_UNSUPPORTED" if still_fail_closed else "NO_TARGET_WITHIN_MODEL"
        result["delta_vs_032"] = {
            "was_fail_closed": baseline_fail_closed,
            "is_fail_closed": still_fail_closed,
            "transitioned_to_no_target_within_v4_model": baseline_fail_closed and not still_fail_closed,
            "transition": f"032_{baseline_state}_TO_033_{current_state}",
            "baseline_discriminators": baseline_discriminators,
        }
        results.append(result)
    results.sort(key=lambda row: parse_hex(row["store_va"], "result store"))
    admission_events = [event for row in results for event in row["v4_handled_forms"]]
    admission_mismatches = _admit_reached_extension_events(admission_events, admission_lookup)
    reached_extension_keys = {(int(event["site_index"]), str(event["va"]), _event_raw_word(event)) for event in admission_events}
    extension_admission = {
        "reached_unique_event_count": len(reached_extension_keys),
        "selected_029_occurrence_count": len(admission_lookup),
        "selected_not_reached_count": len(admission_lookup) - len(reached_extension_keys),
        **admission_mismatches,
        "events_outside_selected": admission_mismatches["events_outside_selected"],
        "family_label_mismatch_count": admission_mismatches["family_mismatch_count"] + admission_mismatches["label_mismatch_count"],
        "all_reached_events_admitted": admission_mismatches["events_outside_selected"] == 0 and admission_mismatches["family_mismatch_count"] == 0 and admission_mismatches["label_mismatch_count"] == 0,
        "exact_selected_identity": len(admission_lookup) == 352,
    }
    counts: dict[str, int] = {}
    residual_forms: dict[str, int] = {}
    handled_forms: dict[str, int] = {}
    for row in results:
        for label in row["discriminators"]:
            counts[label] = counts.get(label, 0) + 1
        for item in row["v4_handled_forms"]:
            handled_forms[item["family"]] = handled_forms.get(item["family"], 0) + 1
        for item in row["unsupported_forms"]:
            residual_forms[item] = residual_forms.get(item, 0) + 1
    residual_sites = [row for row in results if INDIRECT in row["discriminators"]]
    consumer_rows = [row for row in results if "DCB_CONSUMER_PATH" in row["discriminators"]]
    target_rows = [row for row in results if "MC_OR_SHRM_SYMBOLIC_TARGET" in row["discriminators"]]
    selected_membership = _all_range_forms_selected(manifest_029)
    residual_site_indices = {row["site_index"] for row in residual_sites}
    # The 029 rows are exact syntactic range-membership facts.  Retain the
    # residual 032 families verbatim as a separate accounting view; this must
    # not be confused with CFG reachability of any individual occurrence.
    residual_032_range_forms = [
        {
            "site_index": int(item["site_index"]),
            "store_va": item["store_va"],
            "va": item["va"],
            "raw_word": item["raw_word"],
            "family": item["classification"]["family"],
            "label": item["classification"]["label"],
            "reason": item["classification"]["reason"],
            "reachability": "UNKNOWN_029_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY",
        }
        for item in manifest_029["frontier"]["occurrences"]
        if item["classification"]["family"] in RESIDUAL_MEMORY_PREDICTED_FAMILIES
    ]
    residual_032_range_forms.sort(key=lambda item: (parse_hex(item["va"], "residual form VA"), item["site_index"], item["raw_word"]))
    residual_range_forms = [
        {
            "site_index": int(item["site_index"]),
            "store_va": item["store_va"],
            "va": item["va"],
            "raw_word": item["raw_word"],
            "family": item["classification"]["family"],
            "label": item["classification"]["label"],
            "reason": item["classification"]["reason"],
            "reachability": "UNKNOWN_029_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY",
        }
        for item in manifest_029["frontier"]["occurrences"]
        if int(item["site_index"]) in residual_site_indices and item["classification"]["family"] not in PREDICTED_IMPLEMENTED_FAMILIES
    ]
    residual_range_forms.sort(key=lambda item: (parse_hex(item["va"], "residual form VA"), item["site_index"], item["raw_word"]))
    residual_range_counts: dict[str, int] = {}
    for item in residual_range_forms:
            residual_range_counts[item["family"]] = residual_range_counts.get(item["family"], 0) + 1
    residual_032_range_counts: dict[str, int] = {}
    for item in residual_032_range_forms:
        residual_032_range_counts[item["family"]] = residual_032_range_counts.get(item["family"], 0) + 1
    counts.setdefault("DCB_CONSUMER_PATH", 0)
    counts.setdefault("MC_OR_SHRM_SYMBOLIC_TARGET", 0)
    def unique_events(rows: Iterable[Mapping[str, Any]], keys: Sequence[str]) -> list[dict[str, Any]]:
        unique: dict[tuple[Any, ...], dict[str, Any]] = {}
        for row in rows:
            key = tuple(row.get(name) for name in keys)
            unique[key] = dict(row)
        return sorted(unique.values(), key=lambda row: tuple(str(row.get(name, "")) for name in keys))

    reached_extension_events = unique_events(
        (event for row in results for event in row["v4_handled_forms"]),
        ("site_index", "va", "raw_word", "family", "effect"),
    )
    reached_arithmetic_events = [
        event for event in reached_extension_events
        if event.get("family") in ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES
    ]
    arithmetic_lookup = {
        key: value for key, value in admission_lookup.items()
        if value["family"] in ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES
    }
    arithmetic_admission_mismatches = _admit_reached_extension_events(reached_arithmetic_events, arithmetic_lookup)
    reached_taint_kill_events = unique_events(
        (event for row in results for event in row["taint_kills"]),
        ("site_index", "va", "raw_word", "family", "destination", "reason"),
    )
    reached_blocker_events = unique_events(
        (event for row in results for event in row["reached_blocker_events"]),
        ("site_index", "va", "raw_word", "family", "effect"),
    )
    direct_control_events = unique_events(
        (event for row in results for event in row["control_flow_events"]),
        ("site_index", "va", "raw_word", "family", "effect"),
    )
    direct_control_family_counts: dict[str, int] = {}
    for event in direct_control_events:
        family = str(event.get("control_family", "UNKNOWN_DIRECT_CONTROL"))
        direct_control_family_counts[family] = direct_control_family_counts.get(family, 0) + 1
    # 032's inherited set is all 264 reached extension records, including
    # its 14 arithmetic events.  Only the 44 newly-reached residual-memory /
    # system records are excluded from this exact equality gate.
    inherited_extension_events = [
        event for event in reached_extension_events
        if event.get("family") not in RESIDUAL_MEMORY_PREDICTED_FAMILIES
    ]
    inherited_expected_events = list(manifest_032["analysis"]["reached_extension_events"])
    inherited_extension_equivalence = assert_inherited_032_equivalence(
        inherited_expected_events,
        inherited_extension_events,
        "reached_extension_events",
    )
    inherited_expected_control = unique_events(
        (event for row in manifest_032["sites"] for event in row.get("control_flow_events", [])),
        ("site_index", "va", "raw_word", "family", "effect"),
    )
    inherited_control_equivalence = assert_inherited_032_equivalence(
        inherited_expected_control,
        direct_control_events,
        "direct_control_events",
    )
    inherited_taint_equivalence = assert_inherited_032_equivalence(
        manifest_032["analysis"]["reached_taint_kill_events"],
        reached_taint_kill_events,
        "reached_taint_kill_events",
    )
    inherited_032_equivalence = {
        "canonicalization": "JSON_SORT_KEYS_COMPACT_FULL_RECORD",
        "reached_extension_events": inherited_extension_equivalence,
        "direct_control_events": inherited_control_equivalence,
        "reached_taint_kill_events": inherited_taint_equivalence,
        "all_checks_exact": all(
            check["exact_full_record_equality"]
            for check in (inherited_extension_equivalence, inherited_control_equivalence, inherited_taint_equivalence)
        ),
    }
    operation_counts = Counter(
        str(event.get("operation"))
        for event in reached_arithmetic_events
    )
    expected_operation_counts = {"MADD": 3, "UMADDL": 7, "EOR": 2, "BIC": 2}
    if dict(sorted(operation_counts.items())) != expected_operation_counts:
        raise ExtensionError(f"arithmetic operation identity mismatch: {dict(operation_counts)}")
    reached_residual_events = [
        event for event in reached_extension_events
        if event.get("family") in RESIDUAL_MEMORY_PREDICTED_FAMILIES
    ]
    residual_operation_counts = Counter(str(event.get("operation")) for event in reached_residual_events)
    expected_residual_operation_counts = {"DAIFClr": 1, "LDP": 38, "LDRSB": 1, "LDRSW": 1, "STP": 3}
    if dict(sorted(residual_operation_counts.items())) != expected_residual_operation_counts:
        raise ExtensionError(f"residual operation identity mismatch: {dict(residual_operation_counts)}")
    residual_pair_events = [event for event in reached_residual_events if event.get("family") == PAIR_MEMORY]
    residual_sign_events = [event for event in reached_residual_events if event.get("family") == SIGN_EXTENDING_MEMORY]
    residual_system_events = [event for event in reached_residual_events if event.get("family") == SYSTEM_CONTROL]
    residual_selected_occurrences = [item for item in manifest_029["frontier"]["occurrences"] if item["classification"]["family"] in RESIDUAL_MEMORY_PREDICTED_FAMILIES]
    residual_reached_keys = {(int(event["site_index"]), str(event["va"]), _event_raw_word(event)) for event in reached_residual_events}
    residual_selected_keys = {(int(item["site_index"]), str(item["va"]), str(item["raw_word"])) for item in residual_selected_occurrences}
    residual_admission = {
        "selected_029_occurrence_count": len(residual_selected_keys),
        "reached_unique_event_count": len(residual_reached_keys),
        "selected_not_reached_count": len(residual_selected_keys - residual_reached_keys),
        "events_outside_selected": len(residual_reached_keys - residual_selected_keys),
        "exact_selected_identity": len(residual_selected_keys) == 54,
    }
    if residual_admission["selected_029_occurrence_count"] != 54 or residual_admission["reached_unique_event_count"] != 44 or residual_admission["selected_not_reached_count"] != 10 or residual_admission["events_outside_selected"] != 0 or not residual_admission["exact_selected_identity"]:
        raise ExtensionError(f"residual selected/reached accounting mismatch: {residual_admission}")
    residual_family_admission: dict[str, dict[str, int]] = {}
    selected_by_family: dict[str, set[tuple[int, str, str]]] = {family: set() for family in RESIDUAL_MEMORY_PREDICTED_FAMILIES}
    for item in residual_selected_occurrences:
        selected_by_family[item["classification"]["family"]].add((int(item["site_index"]), str(item["va"]), str(item["raw_word"])))
    for family in sorted(RESIDUAL_MEMORY_PREDICTED_FAMILIES):
        selected_family = selected_by_family[family]
        reached_family = {(int(event["site_index"]), str(event["va"]), _event_raw_word(event)) for event in reached_residual_events if event.get("family") == family}
        residual_family_admission[family] = {
            "selected_029_occurrence_count": len(selected_family),
            "reached_unique_event_count": len(reached_family),
            "selected_not_reached_count": len(selected_family - reached_family),
        }
    stp_observations = [
        observation
        for row in results
        for observation in row.get("target_observations", [])
        if observation.get("kind") == "STP"
    ]
    if len(residual_pair_events) != 41 or len(residual_sign_events) != 2 or len(residual_system_events) != 1 or len(stp_observations) != 6 or {observation.get("pair_lane") for observation in stp_observations} != {0, 1}:
        raise ExtensionError("residual reached family/lane accounting mismatch")
    with_control = [row for row in results if row["control_flow_events"]]
    without_control = [row for row in results if not row["control_flow_events"]]
    direct_control_repair = {
        "repair_id": "DIRECT_CONTROL_DISPATCH_REPAIR",
        "source_family": "DIRECT_CONTROL_DISPATCH_REPAIR",
        "event_count": len(direct_control_events),
        "site_count": len(with_control),
        "family_counts": dict(sorted(direct_control_family_counts.items())),
        "expected_identity": {"event_count": 143, "site_count": 62, "family_counts": {"B.cond": 87, "CBZ_CBNZ": 28, "B": 15, "TBZ_TBNZ": 13}},
        "identity_check": len(direct_control_events) == 143 and len(with_control) == 62 and direct_control_family_counts == {"B": 15, "B.cond": 87, "CBZ_CBNZ": 28, "TBZ_TBNZ": 13},
        "outcome_split": {
            "with_direct_control_repair": {"site_count": len(with_control), "no_target_within_v4_model": sum("NO_TARGET_WITHIN_MODEL" in row["discriminators"] for row in with_control), "fail_closed": sum(INDIRECT in row["discriminators"] for row in with_control)},
            "without_direct_control_repair": {"site_count": len(without_control), "no_target_within_v4_model": sum("NO_TARGET_WITHIN_MODEL" in row["discriminators"] for row in without_control), "fail_closed": sum(INDIRECT in row["discriminators"] for row in without_control)},
        },
        "source_pages": [54, 55, 111, 112, 849, 850],
        "scope": "bounded direct CFG dispatch only; no runtime target authority or absence claim",
    }
    selected_syntactic = [item for item in manifest_029["frontier"]["occurrences"] if item["classification"]["family"] in PREDICTED_IMPLEMENTED_FAMILIES]
    actual_closed = [row for row in results if row["delta_vs_027"]["transitioned_to_no_target_within_v4_model"]]
    actual_closed_vs_032 = [row for row in results if row["delta_vs_032"]["transitioned_to_no_target_within_v4_model"]]
    transition_quadrants = validate_032_to_033_transition_quadrants(results)
    selected_old = [item for item in manifest_029["frontier"]["occurrences"] if item["classification"]["family"] in V2_PREDICTED_IMPLEMENTED_FAMILIES]
    selected_arithmetic = [item for item in manifest_029["frontier"]["occurrences"] if item["classification"]["family"] in ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES]
    selected_unique = {item["va"] for item in selected_syntactic}
    selected_words = {item["raw_word"] for item in selected_syntactic}
    arithmetic_unique = {item["va"] for item in selected_arithmetic}
    arithmetic_words = {item["raw_word"] for item in selected_arithmetic}
    residual_unique = {item["va"] for item in residual_range_forms}
    residual_words = {item["raw_word"] for item in residual_range_forms}
    return {
        "site_count": 71,
        "results": results,
        "discriminator_counts": dict(sorted(counts.items())),
        "actual_delta_vs_027": {"baseline_fail_closed_sites": 71, "v4_fail_closed_sites": len(residual_sites), "sites_remaining_fail_closed": len(residual_sites), "sites_transitioned_to_no_target_within_v4_model": len(actual_closed), "transition_identity": len(residual_sites) + len(actual_closed) == 71, "transition_scope": "V4_MODEL_ONLY", "combined_scalar_plus_dispatch_v4": True, "dispatch_dependency": "DIRECT_CONTROL_DISPATCH_REPAIR", "absence_claim": "NO_ABSENCE_CLAIM"},
        "actual_delta_vs_032": {"baseline_fail_closed_sites": 16, "v4_fail_closed_sites": len(residual_sites), "sites_remaining_fail_closed": len(residual_sites), "sites_transitioned_to_no_target_within_v4_model": len(actual_closed_vs_032), "transition_identity": len(residual_sites) + len(actual_closed_vs_032) == 16, "transition_scope": "V4_MODEL_ONLY", "absence_claim": "NO_ABSENCE_CLAIM"},
        "transition_quadrants": transition_quadrants,
        "all_range_forms_selected": selected_membership,
        "handled_frontier_family_counts": dict(sorted(handled_forms.items())),
        "residual_unsupported_form_counts": dict(sorted(residual_forms.items())),
        "remaining_unsupported_sites": [{"site_index": row["site_index"], "store_va": row["store_va"], "families": row["v4_syntactic_frontier"]["families"], "unsupported_forms": row["unsupported_forms"]} for row in residual_sites],
        "remaining_unsupported_range_forms": residual_range_forms,
        "remaining_unsupported_range_form_counts": dict(sorted(residual_range_counts.items())),
        "remaining_unsupported_site_count": len(residual_sites),
        "remaining_unsupported_form_count": len(residual_range_forms),
        "selected_syntactic_frontier": {"occurrence_count": len(selected_syntactic), "unique_va_count": len(selected_unique), "unique_raw_word_count": len(selected_words), "site_count": len({int(item["site_index"]) for item in selected_syntactic}), "classes": sorted(PREDICTED_IMPLEMENTED_FAMILIES), "identity": f"{len(selected_syntactic)} occurrences / {len(selected_unique)} unique VAs / {len(selected_words)} unique raw words across all 71 ranges"},
        "selected_031_syntactic_frontier": {"occurrence_count": len(selected_old), "unique_va_count": len({item["va"] for item in selected_old}), "unique_raw_word_count": len({item["raw_word"] for item in selected_old}), "site_count": len({int(item["site_index"]) for item in selected_old}), "classes": sorted(V2_PREDICTED_IMPLEMENTED_FAMILIES), "identity": "031 selected scalar domain retained exactly"},
        "selected_arithmetic_syntactic_frontier": {"occurrence_count": len(selected_arithmetic), "unique_va_count": len(arithmetic_unique), "unique_raw_word_count": len(arithmetic_words), "site_count": len({int(item["site_index"]) for item in selected_arithmetic}), "classes": sorted(ARITHMETIC_PREDICTED_IMPLEMENTED_FAMILIES), "identity": "MADD/UMADDL + EOR_SHIFT + BIC_SHIFT; range membership is not CFG reachability"},
        "remaining_syntactic_frontier": {"occurrence_count": len(residual_range_forms), "unique_va_count": len(residual_unique), "unique_raw_word_count": len(residual_words), "site_count": len({int(item["site_index"]) for item in residual_range_forms}), "classes": sorted(residual_range_counts), "identity": f"{len(residual_range_forms)} occurrences / {len(residual_unique)} unique VAs / {len(residual_words)} unique raw words remain outside the v4 selected family set; range membership is not CFG reachability"},
        "residual_032_syntactic_frontier": {"occurrence_count": len(residual_032_range_forms), "unique_va_count": len({item["va"] for item in residual_032_range_forms}), "unique_raw_word_count": len({item["raw_word"] for item in residual_032_range_forms}), "site_count": len({int(item["site_index"]) for item in residual_032_range_forms}), "family_counts": dict(sorted(residual_032_range_counts.items())), "classes": sorted(RESIDUAL_MEMORY_PREDICTED_FAMILIES), "identity": "032 residual syntactic membership retained separately from v4 reachability"},
        "reached_extension_events": reached_extension_events,
        "reached_extension_event_count": len(reached_extension_events),
        "reached_residual_events": reached_residual_events,
        "reached_residual_event_count": len(reached_residual_events),
        "residual_operation_counts": {"counts": dict(sorted(residual_operation_counts.items())), "expected_counts": dict(sorted(expected_residual_operation_counts.items())), "identity_check": dict(sorted(residual_operation_counts.items())) == dict(sorted(expected_residual_operation_counts.items()))},
        "reached_pair_event_count": len(residual_pair_events),
        "reached_sign_extending_event_count": len(residual_sign_events),
        "reached_system_event_count": len(residual_system_events),
        "residual_extension_admission": residual_admission,
        "residual_family_admission": residual_family_admission,
        "stp_lane_observation_count": len(stp_observations),
        "stp_lane_indices": sorted({int(observation["pair_lane"]) for observation in stp_observations}),
        "reached_arithmetic_events": reached_arithmetic_events,
        "reached_arithmetic_event_count": len(reached_arithmetic_events),
        "arithmetic_operation_counts": {"counts": dict(sorted(operation_counts.items())), "expected_counts": dict(sorted(expected_operation_counts.items())), "identity_check": dict(sorted(operation_counts.items())) == dict(sorted(expected_operation_counts.items()))},
        "inherited_032_equivalence": inherited_032_equivalence,
        "extension_admission": extension_admission,
        "arithmetic_extension_admission": {"reached_unique_event_count": len(reached_arithmetic_events), "selected_029_occurrence_count": len(arithmetic_lookup), "selected_not_reached_count": len(arithmetic_lookup) - len(reached_arithmetic_events), **arithmetic_admission_mismatches, "all_reached_events_admitted": all(value == 0 for value in arithmetic_admission_mismatches.values()), "exact_selected_identity": len(arithmetic_lookup) == 15},
        "reached_taint_kill_events": reached_taint_kill_events,
        "reached_blocker_events": reached_blocker_events,
        "system_side_effect_events": unique_events((event for row in results for event in row["system_side_effects"]), ("site_index", "va", "raw_word", "family", "effect")),
        "direct_control_dispatch_repair": direct_control_repair,
        "dcb_consumer_paths": [{"site_index": row["site_index"], "store_va": row["store_va"]} for row in consumer_rows],
        "mc_or_shrm_target_paths": [{"site_index": row["site_index"], "store_va": row["store_va"]} for row in target_rows],
        "writer_absence": "UNKNOWN",
        "writer_absence_claim": False,
    }


def definition_of_done() -> dict[str, Any]:
    na = "NOT_APPLICABLE: host-only static analysis; no device or persistent state was touched"
    return {
        "date": "2026-08-26",
        "timestamp": {"value": "NOT_APPLICABLE", "reason": "Deterministic host-only publication omits wall-clock time."},
        "target": {"marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855", "binding": "PROVED_EXACT_FIRMWARE_INPUT_HASH"},
        "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256, "build": "UNKNOWN"},
        "precondition": {"status": "PROVED", "device_access": "none", "exact": "Exact XBL plus exact-hash-pinned 032/029/031/027 source/public inputs; no device action."},
        "result": {"classification": "CLASS C (TRANSFORM ONLY)", "status": "BOUNDED_RESIDUAL_MEMORY_AND_SYSTEM_EXTENSION_UNKNOWN_GLOBAL", "proved": "Exact input identity, source/manifest pins, inherited 032 arithmetic/scalar/direct-control semantics, qualified pair/sign-extending/system masks, bounded CFG, and deterministic accounting.", "supported": "Only the explicitly qualified 032 forms plus LDP/STP integer residual forms, LDRSW/LDRSB unsigned-immediate forms, exact DAIFClr IRQ/PSTATE instruction semantics, and bounded direct-control dispatch repair.", "unknown": "Runtime aliases, current destinations, unsupported forms, execution/order, DAIFClr current-EL/access-trap outcome, protected-memory semantics, and global consumer/writer presence remain UNKNOWN."},
        "non_applicable_artifacts": {name: {"status": "NOT_APPLICABLE", "reason": na} for name in ("boot", "kernel", "dtb", "research_kernel")},
        "live_repetitions": {"status": "NOT_APPLICABLE", "reason": na},
        "dmesg": {"status": "NOT_APPLICABLE", "reason": na},
        "log": {"status": "NOT_APPLICABLE", "reason": na},
        "rollback": {"status": "NOT_APPLICABLE", "reason": na},
        "recovery": {"status": "NOT_APPLICABLE", "reason": na},
        "negative_controls": {"status": "PASS", "description": "Exact hash/semantic mutation, reserved encodings, unsafe forms, source provenance, CFG limits, and no-clobber publication fail closed."},
        "deterministic_repetition_validation": {"repetition_count": 2, "repetition_unit": "fresh host manifest generations", "repetition_result": "BYTE_IDENTICAL", "validation_checks": ["exact XBL and 032/031/029/027 source/public hashes", "032 semantic 55/16 boundary, quadrants, inherited equivalence, arithmetic counts, and exact 71-site identity", "qualified Arm-source LDP/STP/LDRSW/LDRSB/DAIFClr masks and modulo64 writeback semantics", "pre-state pair lanes, overlap and ZR discard controls", "DIRECT_CONTROL_DISPATCH_REPAIR inherited event/site/family accounting", "residual pair/sign-extending/system/indirect reachability accounting", "O_EXCL/O_NOFOLLOW mode0644 publication"]},
        "tool_and_build": {"tool": "sm8150_dcb_residual_memory_frontier.py", "build": "NOT_APPLICABLE", "build_reason": "Interpreted host transform; no firmware/kernel build."},
    }


def build_manifest(
    firmware_dir: Path = FIRMWARE_DIR,
    manifest_dir: Path = MANIFEST_DIR,
    tool_032_path: Path | None = None,
    manifest_032_path: Path | None = None,
    tool_031_path: Path | None = None,
    manifest_031_path: Path | None = None,
    tool_029_path: Path | None = None,
    manifest_029_path: Path | None = None,
    tool_027_path: Path | None = None,
    manifest_027_path: Path | None = None,
) -> dict[str, Any]:
    decoder, dep032, dep029, hashes = load_pinned_dependencies(
        tool_032_path=tool_032_path,
        manifest_032_path=manifest_032_path or Path(manifest_dir) / EXPERIMENT_032_MANIFEST_NAME,
        tool_031_path=tool_031_path,
        manifest_031_path=manifest_031_path or Path(manifest_dir) / EXPERIMENT_031_MANIFEST_NAME,
        tool_027_path=tool_027_path,
        manifest_027_path=manifest_027_path or Path(manifest_dir) / EXPERIMENT_027_MANIFEST_NAME,
        tool_029_path=tool_029_path,
        manifest_029_path=manifest_029_path or Path(manifest_dir) / EXPERIMENT_029_MANIFEST_NAME,
    )
    firmware = load_exact(Path(firmware_dir) / XBL_NAME, XBL_SIZE, XBL_SHA256, XBL_NAME)
    analysis = analyze_exact_sites(decoder, dep032, dep029, firmware)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, **hashes},
        "scope": {"source_experiment": "032-dcb-arithmetic-frontier", "frontier_source": "029-dcb-unsupported-frontier", "fail_closed_site_count": 71, "scan_mode": "BOUNDED_CFG_DATAFLOW_ONLY", "cfg_reachability": "ANALYZED_WITHIN_SITE_RANGE_ONLY", "arbitrary_range_scan": False, "device_mmio_write": False, "global_writer_absence": "UNKNOWN", "writer_absence_claim": False, "inherited_032": "EXACT_FULL_RECORD_EQUALITY_264_143_23", "selected_frontier": "EXACT_029_FULL_352_OCCURRENCES", "residual_memory_admission": "LDP_W_X_SIGNED_OFFSET_LDP_X_POSTINDEX_STP_W_X_SIGNED_OFFSET", "sign_extending_admission": "LDRSW_X_LDRSB_W_UNSIGNED_IMMEDIATE", "system_admission": "DAIFCLR_IRQ_PSTATE_INSTRUCTION_SEMANTICS_ONLY", "system_execution_context": "UNKNOWN_CURRENT_EL_CHECKDAIFACCESS_TRAP_OUTCOME", "direct_control_dispatch_repair": "DIRECT_CONTROL_DISPATCH_REPAIR_INHERITED", "combined_result_scope": "V4_MODEL_ONLY_NO_ABSENCE_CLAIM", "preserved_fail_closed_families": ["UNSUPPORTED_PAIR_VARIANT", "UNSUPPORTED_SIGN_EXTENDING_VARIANT", "SYSTEM_CONTROL_OTHER_THAN_DAIFCLR", "INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS", "UNKNOWN_FORM"]},
        "architecture_sources": {"primary": ARM_PRIMARY_SOURCE, "qualified_forms": ARM_FORM_SOURCES, "qualification_rule": "A form is promoted only when the pinned official Arm source is available and its encoding/operation agrees with the implementation; otherwise it remains UNKNOWN and fail-closed."},
        "dependency_032": {"classification": dep032["classification"], "experiment_id": dep032["experiment_id"], "schema": dep032.get("schema"), "site_count": dep032["analysis"]["site_count"], "fail_closed_site_count": dep032["analysis"]["discriminator_counts"][INDIRECT], "writer_absence": dep032["analysis"]["writer_absence"], "writer_absence_claim": dep032["analysis"]["writer_absence_claim"], "transitioned_to_no_target_within_v3_model": dep032["analysis"]["actual_delta_vs_027"]["sites_transitioned_to_no_target_within_v3_model"], "semantic_pins": {"discriminator_counts": dep032["analysis"]["discriminator_counts"], "transition_quadrants": dep032["analysis"]["transition_quadrants"]["counts"], "inherited_equivalence_counts": {name: dep032["analysis"]["inherited_031_equivalence"][name]["expected_count"] for name in ("reached_extension_events", "direct_control_events", "reached_taint_kill_events")}, "arithmetic_operation_counts": dep032["analysis"]["arithmetic_operation_counts"]["counts"]}},
        "dependency_029": {"classification": dep029["classification"], "fail_closed_site_count": dep029["scope"]["fail_closed_site_count"], "frontier_occurrence_count": dep029["accounting"]["frontier_occurrence_count"], "frontier_unique_va_count": dep029["accounting"]["frontier_unique_va_count"], "frontier_unique_raw_word_count": dep029["accounting"]["frontier_unique_raw_word_count"], "class_counts": dep029["frontier"]["class_counts"]},
        "analysis": {key: value for key, value in analysis.items() if key not in {"results"}},
        "sites": analysis["results"],
        "claims": {"PROVED": ["Each imported 032/031/027 source was size/hash-validated before its own import; the 032/031/029/027 public manifests were also size/hash- and semantics-validated before use. The exact XBL size/hash was validated separately before analysis.", "Exactly the same 71 027 fail-closed site identities and inherited 032 scalar/arithmetic/direct-control records were analyzed within their bounded ranges.", "The complete 029 frontier is selected as 352 syntactic occurrences; the measured admission is 308 reached events and 44 selected-not-reached occurrences, including 264 inherited 032 events and 44 new residual events.", "The measured bounded site outcome is 70 NO_TARGET_WITHIN_MODEL and 1 INDIRECT_OR_UNSUPPORTED, with the latter remaining at site 35; no DCB consumer or MC/SHRM target path is promoted.", "Only source-qualified integer LDP/STP, LDRSW/LDRSB, and exact DAIFClr forms are promoted; pair lanes, decoded fields, and system instruction boundaries are published.", "DIRECT_CONTROL_DISPATCH_REPAIR is inherited as bounded direct-CFG evidence with no runtime target authority; its exact event/site/family counts remain published.", "029 range membership is syntactic evidence only and is not CFG reachability, execution order, or closure prediction. Destination-local memory/sign-extension provenance is retained only for exact DCB-derived data; other results remain UNKNOWN."], "SUPPORTED": ["A DCB consumer or MC/SHRM label, if produced by this bounded model, would be symbolic evidence only and would not establish current_destination."], "HYPOTHESIS": ["Resolving site 35's indirect/runtime target may determine whether the final bounded fail-closed site contains a DCB consumer or MC/SHRM symbolic target path."], "REFUTED": [], "UNKNOWN": ["Unknown loads and arithmetic results are destination-local UNKNOWN values, not absence evidence.", "STP observations do not establish a runtime writer or consumer absence claim.", "The runtime exception level and CheckDAIFAccess outcome for the exact DAIFClr instruction are UNKNOWN; the event records instruction semantics, not proof that the side effect executed without a trap.", "Indirect/runtime aliases, execution order, protected-memory semantics, current destinations, and global DCB consumer/writer presence remain UNKNOWN."]},
        "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "mmio": "none", "smc": "none", "write": "none", "reason": "Host-only read-only transform; no activation or live authority."},
        "reproducibility": {"generation_mode": "DETERMINISTIC_SORTED_JSON", "repetition_count": 2, "repetition_result": "BYTE_IDENTICAL", "publication": "O_EXCL_O_NOFOLLOW_MODE_0644"},
        "definition_of_done": definition_of_done(),
        "reproducible_command_template": "python3 tools/sm8150_dcb_residual_memory_frontier.py --firmware-dir <exact-firmware-dir> --manifest-dir <public-manifest-dir> --output <public-manifest-path>",
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
    parser.add_argument("--tool-032", type=Path, default=None)
    parser.add_argument("--manifest-032", type=Path, default=None)
    parser.add_argument("--tool-031", type=Path, default=None)
    parser.add_argument("--manifest-031", type=Path, default=None)
    parser.add_argument("--tool-027", type=Path, default=None)
    parser.add_argument("--manifest-027", type=Path, default=None)
    parser.add_argument("--tool-029", type=Path, default=None)
    parser.add_argument("--manifest-029", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir, args.manifest_dir, args.tool_032, args.manifest_032, args.tool_031, args.manifest_031, args.tool_029, args.manifest_029, args.tool_027, args.manifest_027)
    encoded = (json.dumps(manifest, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
    write_no_clobber(args.output, encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
