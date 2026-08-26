#!/usr/bin/env python3
"""Host-only Experiment 029: inventory the unsupported frontier left by 027.

Experiment 027 deliberately failed closed when its small AArch64 decoder saw a
form it did not implement.  This stage inventories those exact forms inside
the 71 fail-closed ranges recorded by the 027 public manifest.  It is a
syntactic inventory: membership in a dependency range is not a CFG
reachability claim, and no decoder extension is enabled by this module.

The 027 module is loaded lazily, *after* its exact source size and SHA-256 have
been checked.  The public output contains raw instruction words, virtual
addresses, and accounting metadata only.  It never contains firmware bytes,
private paths, device state, or a current destination claim.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
MANIFEST_DIR = REPO_ROOT / "evidence/manifests"
XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

EXPERIMENT_027_TOOL_NAME = "sm8150_dcb_consumer_writer_complement.py"
EXPERIMENT_027_TOOL_SIZE = 86_782
EXPERIMENT_027_TOOL_SHA256 = "11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9"
EXPERIMENT_027_MANIFEST_NAME = "027-dcb-consumer-writer-complement-20260826-01.manifest.json"
EXPERIMENT_027_MANIFEST_SIZE = 334_847
EXPERIMENT_027_MANIFEST_SHA256 = "d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277"

SCHEMA = "sm8150-dcb-unsupported-frontier-v1"
EXPERIMENT_ID = "029-dcb-unsupported-frontier"
MODE = "HOST_ONLY_READ_ONLY"

DECODER_EXTENSION_CANDIDATE = "DECODER_EXTENSION_CANDIDATE"
FLAG_ONLY_NO_GPR_DEF = "FLAG_ONLY_NO_GPR_DEF"
TAINT_KILL_REQUIRED = "TAINT_KILL_REQUIRED"
CONTROL_OR_MEMORY_UNSUPPORTED = "CONTROL_OR_MEMORY_UNSUPPORTED"
UNREACHABLE_OR_OVERLAP_UNKNOWN = "UNREACHABLE_OR_OVERLAP_UNKNOWN"
UNKNOWN = "UNKNOWN"

REQUIRED_CLASSES = (
    DECODER_EXTENSION_CANDIDATE,
    FLAG_ONLY_NO_GPR_DEF,
    TAINT_KILL_REQUIRED,
    CONTROL_OR_MEMORY_UNSUPPORTED,
    UNREACHABLE_OR_OVERLAP_UNKNOWN,
)


class FrontierError(ValueError):
    """Raised when a pinned input or fail-closed boundary is malformed."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value: int) -> str:
    return f"0x{value:08x}"


def _parse_hex(value: Any, label: str) -> int:
    if not isinstance(value, str) or not value.lower().startswith("0x"):
        raise FrontierError(f"{label} is not a hexadecimal string")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise FrontierError(f"{label} is not hexadecimal") from exc
    if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise FrontierError(f"{label} is outside the supported address width")
    return parsed


def load_exact(path: Path, size: int, digest: str, label: str) -> bytes:
    if not path.is_file():
        raise FrontierError(f"missing exact input: {label}")
    data = path.read_bytes()
    actual = sha256(data)
    if len(data) != size or actual != digest:
        raise FrontierError(f"exact input mismatch: {label}")
    return data


def _validate_027_semantics(manifest: Mapping[str, Any]) -> None:
    """Validate the 027 contract before using any of its site ranges."""

    if manifest.get("experiment_id") != "027-dcb-consumer-writer-complement":
        raise FrontierError("Experiment 027 identity changed")
    if manifest.get("mode") != MODE:
        raise FrontierError("Experiment 027 mode changed")
    if manifest.get("classification") != "CLASS C (TRANSFORM ONLY)":
        raise FrontierError("Experiment 027 classification changed")
    if manifest.get("device_access") != "none" or manifest.get("eligibility") != "NOT_ELIGIBLE":
        raise FrontierError("Experiment 027 authority boundary changed")

    firmware = manifest.get("inputs", {}).get("firmware", {})
    if (
        firmware.get("filename") != XBL_NAME
        or firmware.get("size") != XBL_SIZE
        or firmware.get("sha256") != XBL_SHA256
    ):
        raise FrontierError("Experiment 027 firmware input pin changed")

    summary = manifest.get("site_summary")
    scope = manifest.get("scope")
    rows = manifest.get("sites")
    if not isinstance(summary, Mapping) or not isinstance(scope, Mapping) or not isinstance(rows, list):
        raise FrontierError("Experiment 027 site contract is malformed")
    if (
        summary.get("site_count") != 73
        or summary.get("register_offset_site_count") != 65
        or summary.get("computed_address_site_count") != 8
        or len(rows) != 73
        or scope.get("register_offset_sites") != 67
        or scope.get("computed_address_idioms") != 8
    ):
        raise FrontierError("Experiment 027 site cardinality changed")

    discriminator_counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("discriminators"), list):
            raise FrontierError("Experiment 027 site row is malformed")
        for label in row["discriminators"]:
            discriminator_counts[label] = discriminator_counts.get(label, 0) + 1
    if discriminator_counts.get("INDIRECT_OR_UNSUPPORTED") != 71:
        raise FrontierError("Experiment 027 fail-closed site count changed")
    if discriminator_counts.get("NO_TARGET_WITHIN_MODEL") != 2:
        raise FrontierError("Experiment 027 no-target site count changed")
    if discriminator_counts.get("DCB_CONSUMER_PATH", 0) != 0:
        raise FrontierError("Experiment 027 DCB consumer label is not zero")
    if discriminator_counts.get("MC_OR_SHRM_SYMBOLIC_TARGET", 0) != 0:
        raise FrontierError("Experiment 027 MC/SHRM label is not zero")
    if summary.get("discriminator_counts", {}).get("INDIRECT_OR_UNSUPPORTED") != 71:
        raise FrontierError("Experiment 027 summary fail-closed count changed")
    if summary.get("discriminator_counts", {}).get("NO_TARGET_WITHIN_MODEL") != 2:
        raise FrontierError("Experiment 027 summary no-target count changed")
    if summary.get("writer_absence") != "UNKNOWN" or summary.get("writer_absence_claim") is not False:
        raise FrontierError("Experiment 027 writer-absence boundary changed")
    if scope.get("global_writer_absence") != "UNKNOWN" or scope.get("writer_absence_claim") is not False:
        raise FrontierError("Experiment 027 global writer-absence boundary changed")


def load_pinned_027(
    tool_path: Path | None = None,
    manifest_path: Path | None = None,
) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """Hash-check and semantically validate 027, then import it.

    The import is intentionally the last operation in this function.  This is
    important for hostile dependency tests: a changed decoder source must not
    execute merely because a caller attempted to load the frontier tool.
    """

    tool_path = Path(tool_path) if tool_path is not None else REPO_ROOT / "tools" / EXPERIMENT_027_TOOL_NAME
    manifest_path = Path(manifest_path) if manifest_path is not None else MANIFEST_DIR / EXPERIMENT_027_MANIFEST_NAME
    tool_data = load_exact(tool_path, EXPERIMENT_027_TOOL_SIZE, EXPERIMENT_027_TOOL_SHA256, EXPERIMENT_027_TOOL_NAME)
    manifest_data = load_exact(
        manifest_path,
        EXPERIMENT_027_MANIFEST_SIZE,
        EXPERIMENT_027_MANIFEST_SHA256,
        EXPERIMENT_027_MANIFEST_NAME,
    )
    try:
        manifest = json.loads(manifest_data)
    except json.JSONDecodeError as exc:
        raise FrontierError("Experiment 027 dependency is not JSON") from exc
    if not isinstance(manifest, dict):
        raise FrontierError("Experiment 027 dependency root is not an object")
    _validate_027_semantics(manifest)

    module_name = "_sm8150_exp027_pinned_" + EXPERIMENT_027_TOOL_SHA256[:16]
    spec = importlib.util.spec_from_file_location(module_name, tool_path)
    if spec is None or spec.loader is None:
        raise FrontierError("unable to construct the pinned Experiment 027 import")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module, manifest, {
        "tool": {"filename": EXPERIMENT_027_TOOL_NAME, "size": len(tool_data), "sha256": sha256(tool_data)},
        "manifest": {"filename": EXPERIMENT_027_MANIFEST_NAME, "size": len(manifest_data), "sha256": sha256(manifest_data)},
    }


def validate_027_semantics(manifest: Mapping[str, Any]) -> None:
    """Public semantic validator used by focused and hostile tests."""

    _validate_027_semantics(manifest)


def _decoder_recognizes(decoder: Any, word: int, va: int) -> bool:
    """Mirror the exact instruction dispatch order in 027.

    This function only asks whether 027 has a decoder path for the raw word;
    it does not execute the 027 dataflow or make any reachability claim.
    """

    if decoder.decode_bl_target(word, va) is not None:
        return True
    if decoder.is_blr(word) is not None or decoder.is_br(word) is not None:
        return True
    if decoder.is_ret(word):
        return True
    if decoder.decode_b_target(word, va) is not None:
        return True
    if decoder.adr_target(word, va) is not None or decoder.adrp_target(word, va) is not None:
        return True
    for function in (
        decoder.is_movz,
        decoder.is_movk,
        decoder.is_movn,
        decoder.is_orr_imm,
        decoder.is_and_imm,
        decoder.is_orr_reg,
        decoder.is_add_sub_imm,
        decoder.is_add_sub_reg,
        decoder.is_add_sub_ext,
    ):
        if function(word) is not None:
            return True
    if decoder._decode_mem(word) is not None:
        return True
    if decoder.is_atomic_or_exclusive(word):
        return True
    return decoder._is_nop(word)


def _valid_logical_shifted(word: int) -> tuple[str, bool] | None:
    """Return logical-shifted family and validity, preserving reserved bits."""

    # AArch64 logical-shifted uses sf/op/N/fixed bits.  Keep the complete
    # architectural opcode mask here; the old 0x9f mask dropped op bits and
    # consequently mis-labelled valid AND/BIC/EOR forms as UNKNOWN.
    base = word & 0xFF200000
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
    # Bits 28:24 must be 01010.  The mask above carries sf/op/N while this
    # fixed-field test rejects unrelated data-processing encodings.
    if (word & 0x1F000000) != 0x0A000000 or base not in names:
        return None
    width = 64 if word & 0x80000000 else 32
    amount = (word >> 10) & 0x3F
    # All four shift encodings are architectural, including ROR (shift=3).
    # Only the W-width imm6 range is constrained.
    valid = width == 64 or amount < 32
    return names[base], valid


def _valid_logical_immediate(word: int, decoder: Any) -> tuple[str, bool] | None:
    base = word & 0x7F800000
    names = {
        0x12000000: "AND_IMM",
        0x32000000: "ORR_IMM",
        0x52000000: "EOR_IMM",
        0x72000000: "ANDS_IMM",
    }
    if base not in names:
        return None
    sf = bool(word & 0x80000000)
    width = 64 if sf else 32
    n = (word >> 22) & 1
    valid = not (width == 32 and n)
    if valid:
        valid = decoder._decode_logical_immediate(n, (word >> 16) & 0x3F, (word >> 10) & 0x3F, width) is not None
    return names[base], valid


def _valid_add_sub_immediate(word: int) -> tuple[str, bool] | None:
    if (word & 0x1F000000) not in (0x11000000, 0x51000000, 0x91000000, 0xD1000000):
        return None
    # ADDG/SUBG occupy a neighbouring encoding and carry tagged-pointer
    # semantics outside the small 027 arithmetic model.  Keep them UNKNOWN
    # rather than pretending they are ordinary ADD/SUB immediate forms.
    if word & 0x00800000:
        return "ADD_SUB_IMM_TAGGED_OR_RESERVED", False
    if not (word & 0x20000000):
        # ADD/SUB with Rd=SP is left unsupported by 027 and still matters for
        # taint/stack state, so report it as a GPR/state definition below.
        return "ADD_SUB_IMM_SP", True
    rd = word & 0x1F
    return ("ADDS_SUBS_IMM_FLAG" if rd == 31 else "ADDS_SUBS_IMM", True)


def _valid_add_sub_register(word: int) -> tuple[str, bool] | None:
    if (word & 0x1F200000) not in (0x0B000000, 0x0B200000):
        return None
    extended = bool(word & 0x00200000)
    width = 64 if word & 0x80000000 else 32
    rd = word & 0x1F
    shift_type = (word >> 22) & 3
    amount = (word >> 10) & 0x3F
    sets_flags = bool(word & 0x20000000)
    if extended:
        option = (word >> 13) & 7
        valid_options = set(range(8)) if width == 64 else {0, 1, 2, 4, 5, 6}
        valid = shift_type == 0 and option in valid_options and amount <= 4
        family = "ADDS_SUBS_EXT_FLAG" if sets_flags and rd == 31 else (
            "ADD_SUB_EXT_SP" if rd == 31 else "ADDS_SUBS_EXT"
        )
    else:
        valid = shift_type != 3 and (width == 64 or amount < 32)
        family = "ADDS_SUBS_REG_FLAG" if sets_flags and rd == 31 else (
            "ADD_SUB_REG_ZR_DISCARD" if rd == 31 else "ADDS_SUBS_REG"
        )
    return family, valid


def _valid_bitfield(word: int) -> bool:
    if (word & 0x1F800000) != 0x13000000:
        return False
    sf = 1 if word & 0x80000000 else 0
    n = (word >> 22) & 1
    opc = (word >> 29) & 3
    if opc == 3:
        return False
    if n != sf:
        return False
    width = 64 if sf else 32
    return ((word >> 16) & 0x3F) < width and ((word >> 10) & 0x3F) < width


def _valid_variable_shift(word: int) -> bool:
    return (word & 0x1FE0FC00) in {
        0x1AC02000,
        0x1AC02400,
        0x1AC02800,
        0x1AC02C00,
    }


def _valid_divide(word: int) -> bool:
    return (word & 0x1FE0FC00) in {0x1AC00800, 0x1AC00C00}


def _three_source_major_space(word: int) -> bool:
    """Recognize only the broad major space; do not allocate a multiply form."""

    return (word & 0x1F000000) == 0x1B000000


def _valid_csel(word: int) -> bool:
    if (word & 0x1FE00C00) not in {
        0x1A800000,
        0x1A800400,
    }:
        return False
    return ((word >> 12) & 0xF) < 0xF


def _valid_ccmp(word: int) -> bool:
    if (word & 0x1FE00000) != 0x1A400000:
        return False
    # Conditional compare writes NZCV only.  Reject reserved condition values
    # rather than guessing a semantic extension.
    return ((word >> 12) & 0xF) < 0xF


def _valid_pair_memory(word: int) -> bool:
    # STP/LDP/LDPSW, including offset, pre-index, and post-index forms.
    return (word & 0x3E000000) == 0x28000000


def _valid_signext_memory(word: int) -> bool:
    # Signed-extending scalar loads use the same single-memory families as
    # ordinary byte/half/word loads, but op=10/11 in bits 23:22.  Include
    # unsigned, unscaled, indexed, and register-offset addressing forms.
    return (word & 0x3E000000) == 0x38000000 and ((word >> 22) & 3) in (2, 3)


def classify_unrecognized_word(word: int, decoder: Any | None = None) -> dict[str, Any]:
    """Classify one raw word without asserting reachability or safety.

    The returned ``label`` is deliberately conservative.  A form that does
    not match an exact encoding-mask family remains ``UNKNOWN`` rather than
    being promoted to a safe decoder extension.  A mask match is not primary
    architecture-source provenance.
    """

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        raise FrontierError("raw instruction word is not uint32")
    family: str | None = None
    valid = False
    label = UNKNOWN
    reason = "NO_EXACT_ENCODING_MASK_FAMILY"

    logical = _valid_logical_shifted(word)
    if logical is not None:
        family, valid = logical
        if valid and family in {"ANDS_SHIFT", "BICS_SHIFT"} and (word & 0x1F) == 31:
            label, reason = FLAG_ONLY_NO_GPR_DEF, "flag-setting logical alias writes no GPR"
        elif valid:
            label, reason = DECODER_EXTENSION_CANDIDATE, "exact logical-shifted architectural family"
        else:
            reason = "invalid logical-shifted width/amount encoding"
    else:
        logical_imm = _valid_logical_immediate(word, decoder) if decoder is not None else None
        if logical_imm is not None:
            family, valid = logical_imm
            if valid and family == "ANDS_IMM" and (word & 0x1F) == 31:
                label, reason = FLAG_ONLY_NO_GPR_DEF, "TST alias writes flags only"
            elif valid and family == "ANDS_IMM":
                label, reason = TAINT_KILL_REQUIRED, "flag-setting logical operation defines a GPR"
            elif valid:
                label, reason = DECODER_EXTENSION_CANDIDATE, "exact logical-immediate architectural family"
            else:
                reason = "reserved logical-immediate encoding"
        else:
            add_imm = _valid_add_sub_immediate(word)
            add_reg = _valid_add_sub_register(word)
            if add_imm is not None:
                family, valid = add_imm
                if valid and family.endswith("_FLAG"):
                    label, reason = FLAG_ONLY_NO_GPR_DEF, "CMP/CMN alias writes flags only"
                elif valid:
                    label, reason = TAINT_KILL_REQUIRED, "flag-setting or SP-defining add/sub form"
                else:
                    reason = "reserved add/sub immediate encoding"
            elif add_reg is not None:
                family, valid = add_reg
                if valid and family.endswith("_FLAG"):
                    label, reason = FLAG_ONLY_NO_GPR_DEF, "CMP/CMN register alias writes flags only"
                elif valid and family == "ADD_SUB_REG_ZR_DISCARD":
                    label, reason = UNKNOWN, "S=0 shifted-register Rd=ZR discards result; no GPR definition and flags unchanged"
                elif valid:
                    label, reason = TAINT_KILL_REQUIRED, "flag-setting register add/sub defines a GPR"
                else:
                    reason = "reserved add/sub register encoding"
            elif _valid_ccmp(word):
                family, valid = "CCMP_CCMN", True
                label, reason = FLAG_ONLY_NO_GPR_DEF, "conditional compare writes NZCV only"
            elif _valid_bitfield(word):
                family, valid = "BITFIELD_IMM", True
                label, reason = DECODER_EXTENSION_CANDIDATE, "exact bitfield architectural family"
            elif _valid_variable_shift(word):
                family, valid = "VARIABLE_SHIFT", True
                label, reason = TAINT_KILL_REQUIRED, "variable shift defines a GPR"
            elif _valid_divide(word):
                family, valid = "DIVIDE", True
                label, reason = TAINT_KILL_REQUIRED, "divide defines a GPR"
            elif _three_source_major_space(word):
                family, valid = "THREE_SOURCE_UNVALIDATED", False
                label, reason = UNKNOWN, "primary allocation fields (sf/op54/op31/o0/Ra) not validated"
            elif _valid_csel(word):
                family, valid = "CONDITIONAL_SELECT", True
                label, reason = TAINT_KILL_REQUIRED, "conditional select defines a GPR"
            elif _valid_pair_memory(word):
                family, valid = "PAIR_MEMORY", True
                label, reason = CONTROL_OR_MEMORY_UNSUPPORTED, "pair load/store is outside 027 memory decoder"
            elif _valid_signext_memory(word):
                family, valid = "SIGN_EXTENDING_MEMORY", True
                label, reason = CONTROL_OR_MEMORY_UNSUPPORTED, "sign-extending memory form is outside 027 memory decoder"
            elif (word & 0xFF000000) == 0xD5000000:
                family, valid = "SYSTEM_CONTROL", True
                label, reason = CONTROL_OR_MEMORY_UNSUPPORTED, "system/control form is outside 027 decoder"

    return {
        "raw_word": fmt(word),
        "label": label,
        "family": family or "UNKNOWN_FORM",
        "reason": reason,
        "encoding_mask_match": bool(family and valid),
        "source_provenance": "UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW",
        "reachability": "UNKNOWN_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY",
        "decoder_safety": "NOT_CLAIMED",
    }


def classify_frontier_word(word: int, decoder: Any | None = None) -> dict[str, Any]:
    """Alias retained for callers that use the frontier terminology."""

    return classify_unrecognized_word(word, decoder)


def _range_row(row: Mapping[str, Any], index: int) -> tuple[int, int, int]:
    try:
        range_info = row["range"]
        start = _parse_hex(range_info["start"], f"site {index} range start")
        end = _parse_hex(range_info["end_exclusive"], f"site {index} range end")
        store = _parse_hex(row["store_va"], f"site {index} store")
    except (KeyError, TypeError) as exc:
        raise FrontierError(f"site {index} range is malformed") from exc
    if start >= end or start % 4 or end % 4 or store < start or store >= end:
        raise FrontierError(f"site {index} range is not aligned/ordered")
    return start, end, store


def inventory_frontier(
    decoder: Any,
    manifest_027: Mapping[str, Any],
    firmware: bytes,
) -> dict[str, Any]:
    """Inventory only the exact 71 027 fail-closed ranges."""

    if sha256(firmware) != XBL_SHA256 or len(firmware) != XBL_SIZE:
        raise FrontierError("exact XBL input mismatch")
    _validate_027_semantics(manifest_027)
    image = decoder.Image(firmware)
    rows = [row for row in manifest_027["sites"] if "INDIRECT_OR_UNSUPPORTED" in row["discriminators"]]
    if len(rows) != 71:
        raise FrontierError("exact fail-closed range scope changed")

    occurrence_rows: list[dict[str, Any]] = []
    scanned_rows: list[dict[str, Any]] = []
    range_membership: dict[int, int] = {}
    range_site_indices: dict[int, list[int]] = {}
    recognized_occurrences = 0
    for index, row in enumerate(rows):
        start, end, store = _range_row(row, index)
        per_site: list[dict[str, Any]] = []
        for va in range(start, end, 4):
            word = image.word(va)
            if word is None:
                raise FrontierError(f"site {index} contains an unmapped word")
            range_membership[va] = range_membership.get(va, 0) + 1
            range_site_indices.setdefault(va, []).append(index)
            recognized = _decoder_recognizes(decoder, word, va)
            if recognized:
                recognized_occurrences += 1
            else:
                row_class = classify_unrecognized_word(word, decoder)
                occurrence = {
                    "site_index": index,
                    "store_va": fmt(store),
                    "site_range": {"start": fmt(start), "end_exclusive": fmt(end)},
                    "va": fmt(va),
                    "raw_word": fmt(word),
                    "decoder_status": "UNRECOGNIZED_BY_027",
                    "classification": row_class,
                }
                occurrence_rows.append(occurrence)
                per_site.append(occurrence)
        scanned_rows.append(
            {
                "site_index": index,
                "store_va": fmt(store),
                "site_range": {"start": fmt(start), "end_exclusive": fmt(end), "size": end - start},
                "scanned_word_occurrences": (end - start) // 4,
                "recognized_word_occurrences": (end - start) // 4 - len(per_site),
                "frontier_occurrences": len(per_site),
                "frontier_unique_va_count": len({item["va"] for item in per_site}),
                "frontier_unique_raw_word_count": len({item["raw_word"] for item in per_site}),
                "frontier_overlap_multiplicity": len(per_site) - len({item["va"] for item in per_site}),
                "indirect_runtime_alias": "INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS" in row.get("unsupported_forms", []),
            }
        )

    # Complete the global range-membership map before annotating frontier
    # occurrences. This is orthogonal to primary encoding-family semantics.
    for occurrence in occurrence_rows:
        va = _parse_hex(occurrence["va"], "frontier occurrence VA")
        membership_count = range_membership[va]
        occurrence["range_membership_count"] = membership_count
        occurrence["range_membership_label"] = (
            UNREACHABLE_OR_OVERLAP_UNKNOWN
            if membership_count > 1
            else "UNIQUE_RANGE_MEMBERSHIP"
        )
        occurrence["overlap_status"] = "OVERLAPPING" if membership_count > 1 else "NON_OVERLAPPING"

    occurrence_rows.sort(key=lambda item: (item["va"], item["site_index"], item["raw_word"]))
    unique_vas = sorted({item["va"] for item in occurrence_rows})
    unique_va_records: list[dict[str, Any]] = []
    for va_text in unique_vas:
        members = [item for item in occurrence_rows if item["va"] == va_text]
        raw_words = sorted({item["raw_word"] for item in members})
        if len(raw_words) != 1:
            raise FrontierError(f"frontier VA has inconsistent raw words: {va_text}")
        va = _parse_hex(va_text, "frontier unique VA")
        unique_va_records.append(
            {
                "va": va_text,
                "raw_word": raw_words[0],
                "membership_count": range_membership[va],
                "site_indices": sorted(set(range_site_indices[va])),
                "classification": members[0]["classification"],
            }
        )
    unique_words = sorted({item["raw_word"] for item in occurrence_rows})
    word_rows: list[dict[str, Any]] = []
    for raw_word in unique_words:
        members = [item for item in occurrence_rows if item["raw_word"] == raw_word]
        first = members[0]["classification"]
        word_rows.append(
            {
                "raw_word": raw_word,
                "occurrence_count": len(members),
                "unique_va_count": len({item["va"] for item in members}),
                "unique_site_count": len({item["site_index"] for item in members}),
                "vas": sorted({item["va"] for item in members}),
                "classification": first,
            }
        )

    class_counts: dict[str, int] = {}
    family_counts: dict[str, int] = {}
    for item in occurrence_rows:
        label = item["classification"]["label"]
        family = item["classification"]["family"]
        class_counts[label] = class_counts.get(label, 0) + 1
        family_counts[family] = family_counts.get(family, 0) + 1
    # Keep primary semantic classes explicit, including zero-count classes.
    # UNREACHABLE_OR_OVERLAP_UNKNOWN is orthogonal and is counted separately.
    for label in REQUIRED_CLASSES:
        if label == UNREACHABLE_OR_OVERLAP_UNKNOWN:
            continue
        class_counts.setdefault(label, 0)
    class_counts.setdefault(UNKNOWN, 0)

    range_membership_label_counts = {
        "UNIQUE_RANGE_MEMBERSHIP": sum(
            item["range_membership_count"] == 1 for item in occurrence_rows
        ),
        UNREACHABLE_OR_OVERLAP_UNKNOWN: sum(
            item["range_membership_count"] > 1 for item in occurrence_rows
        ),
    }

    indirect_rows = [
        {
            "site_index": item["site_index"],
            "store_va": item["store_va"],
            "site_range": item["site_range"],
            "reason": "027 recorded INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS; retained separately; no reachability claim",
        }
        for item, row in zip(scanned_rows, rows)
        if item["indirect_runtime_alias"]
    ]
    if len(indirect_rows) != 1:
        raise FrontierError("Experiment 027 indirect/runtime-alias site count changed")

    candidates: list[dict[str, Any]] = []
    for family, count in sorted(family_counts.items()):
        members = [item for item in occurrence_rows if item["classification"]["family"] == family]
        info = members[0]["classification"]
        if info["label"] != DECODER_EXTENSION_CANDIDATE:
            continue
        candidates.append(
            {
                "rank": 0,
                "family": family,
                "label": DECODER_EXTENSION_CANDIDATE,
                "claim_status": "HYPOTHESIS",
                "encoding_mask_match": True,
                "source_provenance": "UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW",
                "occurrence_count": count,
                "unique_va_count": len({item["va"] for item in members}),
                "unique_raw_word_count": len({item["raw_word"] for item in members}),
                "overlap_occurrence_count": sum(
                    item["range_membership_count"] > 1 for item in members
                ),
                "review_status": "HYPOTHESIS_ONLY_PRIMARY_SOURCE_AND_SEMANTIC_REVIEW_REQUIRED",
            }
        )
    rank_basis = "unique_va_count_desc,unique_raw_word_count_desc,occurrence_count_desc,family_asc"
    candidates.sort(
        key=lambda item: (
            -item["unique_va_count"],
            -item["unique_raw_word_count"],
            -item["occurrence_count"],
            item["family"],
        )
    )
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = rank
        candidate["rank_basis"] = rank_basis

    scanned_occurrences = sum(item["scanned_word_occurrences"] for item in scanned_rows)
    scanned_unique_vas = len(range_membership)
    frontier_overlap_unique_va_count = sum(
        range_membership[_parse_hex(va, "frontier unique VA")] > 1 for va in unique_vas
    )
    frontier_nonoverlap_unique_va_count = len(unique_vas) - frontier_overlap_unique_va_count
    return {
        "scope": {
            "source_experiment": "027-dcb-consumer-writer-complement",
            "source_label": "INDIRECT_OR_UNSUPPORTED",
            "fail_closed_site_count": len(rows),
            "register_offset_sites": 65,
            "computed_address_sites": 8,
            "scan_mode": "SYNTACTIC_RANGE_MEMBERSHIP_ONLY",
            "cfg_reachability": "UNKNOWN_NOT_ANALYZED",
            "arbitrary_range_scan": False,
            "device_mmio_write": False,
        },
        "site_ranges": scanned_rows,
        "frontier_occurrences": occurrence_rows,
        "unique_vas": unique_vas,
        "unique_va_records": unique_va_records,
        "unique_raw_words": word_rows,
        "accounting": {
            "site_count": len(rows),
            "scanned_word_occurrence_count": scanned_occurrences,
            "scanned_unique_va_count": scanned_unique_vas,
            "recognized_word_occurrence_count": recognized_occurrences,
            "recognized_unique_va_count": scanned_unique_vas - len(unique_vas),
            "frontier_occurrence_count": len(occurrence_rows),
            "frontier_unique_va_count": len(unique_vas),
            "frontier_unique_raw_word_count": len(word_rows),
            "overlap_multiplicity": len(occurrence_rows) - len(unique_vas),
            "frontier_overlap_occurrence_count": range_membership_label_counts[UNREACHABLE_OR_OVERLAP_UNKNOWN],
            "frontier_nonoverlap_occurrence_count": range_membership_label_counts["UNIQUE_RANGE_MEMBERSHIP"],
            "frontier_overlap_unique_va_count": frontier_overlap_unique_va_count,
            "frontier_nonoverlap_unique_va_count": frontier_nonoverlap_unique_va_count,
            "range_overlap_multiplicity": sum(max(0, count - 1) for count in range_membership.values()),
            "range_membership_label_counts": range_membership_label_counts,
            "frontier_occurrence_identity_check": (
                range_membership_label_counts[UNREACHABLE_OR_OVERLAP_UNKNOWN]
                + range_membership_label_counts["UNIQUE_RANGE_MEMBERSHIP"]
                == len(occurrence_rows)
            ),
            "frontier_unique_va_identity_check": (
                frontier_overlap_unique_va_count + frontier_nonoverlap_unique_va_count
                == len(unique_vas)
            ),
            "range_membership_is_not_reachability": True,
        },
        "class_counts": class_counts,
        "range_membership_label_counts": range_membership_label_counts,
        "family_counts": dict(sorted(family_counts.items())),
        "rank_basis": rank_basis,
        "decoder_extension_candidates": candidates,
        "indirect_runtime_alias_site": indirect_rows[0],
    }


def definition_of_done_metadata() -> dict[str, Any]:
    """Return deterministic host-only completion metadata for Experiment 029."""

    not_applicable = "NOT_APPLICABLE: host-only static analysis; no live device observation or device artifact was used"
    return {
        "date": "2026-08-26",
        "timestamp": {
            "value": "NOT_APPLICABLE",
            "reason": "Deterministic host-only publication does not embed a wall-clock timestamp.",
        },
        "target": {
            "marketing_name": "A90 5G",
            "model": "SM-A908N",
            "soc": "SM8150",
            "soc_name": "Snapdragon 855",
            "binding": "PROVED_EXACT_FIRMWARE_INPUT_HASH",
        },
        "firmware": {
            "filename": XBL_NAME,
            "size": XBL_SIZE,
            "sha256": XBL_SHA256,
            "build": "UNKNOWN",
            "build_reason": "No firmware build identifier is derived by this bounded static inventory.",
        },
        "precondition": {
            "status": "PROVED",
            "device_access": "none",
            "firmware_sha256": XBL_SHA256,
            "dependency_sha256": {
                "tool": EXPERIMENT_027_TOOL_SHA256,
                "manifest": EXPERIMENT_027_MANIFEST_SHA256,
            },
            "exact": "Use only the exact SM-A908N/A90 5G SM8150 XBL input named above, with the exact-hash-pinned Experiment 027 tool and manifest semantically validated before publication; perform no device action.",
        },
        "reproducible_command_template": "python3 tools/sm8150_dcb_unsupported_frontier.py --firmware-dir <exact-firmware-dir> --manifest-dir <public-manifest-dir> --output <public-manifest-path>",
        "result": {
            "classification": "CLASS C (TRANSFORM ONLY)",
            "status": "BOUNDED_UNSUPPORTED_FRONTIER_INVENTORY_UNKNOWN",
            "proved": "Exact XBL/dependency identity and deterministic syntactic range accounting are validated before publication.",
            "supported": "None; encoding-mask matches remain hypotheses pending primary architecture-source and semantic review.",
            "unknown": "Range reachability, source provenance, decoder safety, runtime aliases, current destinations, execution order, and global consumer/writer presence remain UNKNOWN.",
        },
        "non_applicable_artifacts": {
            "boot": {"status": "NOT_APPLICABLE", "reason": not_applicable},
            "kernel": {"status": "NOT_APPLICABLE", "reason": not_applicable},
            "dtb": {"status": "NOT_APPLICABLE", "reason": not_applicable},
            "research_kernel": {"status": "NOT_APPLICABLE", "reason": not_applicable},
        },
        "live_repetitions": {
            "status": "NOT_APPLICABLE",
            "reason": "No live device execution or observation is part of this host-only static experiment.",
        },
        "dmesg": {"status": "NOT_APPLICABLE", "reason": not_applicable},
        "log": {"status": "NOT_APPLICABLE", "reason": not_applicable},
        "rollback": {
            "status": "NOT_APPLICABLE",
            "reason": "No device or persistent state was changed; there is no effect to roll back.",
        },
        "recovery": {
            "status": "NOT_APPLICABLE",
            "reason": "No device, boot, transport, or runtime state was touched.",
        },
        "negative_controls": {
            "status": "PASS",
            "description": "Exact input/hash/ELF/dependency mismatch and no-clobber publication fail closed; no decoder safety or reachability is promoted.",
        },
        "deterministic_repetition_validation": {
            "repetition_count": 2,
            "repetition_unit": "fresh host manifest generations",
            "repetition_result": "BYTE_IDENTICAL",
            "validation_checks": [
                "exact XBL and Experiment 027 source/manifest size/SHA-256",
                "Experiment 027 semantic boundary and 73/65/8 site accounting",
                "exact 71 fail-closed range scan with overlap accounting",
                "conservative encoding-mask classification with UNKNOWN provenance",
                "O_EXCL/O_NOFOLLOW mode0644 and deterministic publication",
            ],
        },
        "tool_and_build": {
            "tool": "sm8150_dcb_unsupported_frontier.py",
            "build": "NOT_APPLICABLE",
            "build_reason": "The host-only analyzer is interpreted Python source and produces no firmware/kernel build output.",
        },
    }


def build_manifest(
    firmware_dir: Path = FIRMWARE_DIR,
    manifest_dir: Path = MANIFEST_DIR,
    tool_path: Path | None = None,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    # The CLI manifest directory is part of the explicit input contract.  Do
    # not silently fall back to the repository default when a caller supplies
    # an alternate exact public-artifact directory.
    if manifest_path is None:
        manifest_path = Path(manifest_dir) / EXPERIMENT_027_MANIFEST_NAME
    decoder, dependency, dependency_hashes = load_pinned_027(tool_path, manifest_path)
    firmware_path = Path(firmware_dir) / XBL_NAME
    firmware = load_exact(firmware_path, XBL_SIZE, XBL_SHA256, XBL_NAME)
    inventory = inventory_frontier(decoder, dependency, firmware)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {
            "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256},
            "experiment_027_tool": dependency_hashes["tool"],
            "experiment_027_manifest": dependency_hashes["manifest"],
        },
        "dependency_027_semantics": {
            "classification": dependency.get("classification"),
            "site_count": dependency["site_summary"]["site_count"],
            "register_offset_site_count": dependency["site_summary"]["register_offset_site_count"],
            "computed_address_site_count": dependency["site_summary"]["computed_address_site_count"],
            "indirect_or_unsupported": dependency["site_summary"]["discriminator_counts"]["INDIRECT_OR_UNSUPPORTED"],
            "no_target_within_model": dependency["site_summary"]["discriminator_counts"]["NO_TARGET_WITHIN_MODEL"],
            "writer_absence": dependency["site_summary"]["writer_absence"],
            "writer_absence_claim": dependency["site_summary"]["writer_absence_claim"],
            "dcb_consumer_path": dependency["site_summary"]["discriminator_counts"].get("DCB_CONSUMER_PATH", 0),
            "mc_or_shrm_symbolic_target": dependency["site_summary"]["discriminator_counts"].get("MC_OR_SHRM_SYMBOLIC_TARGET", 0),
        },
        "scope": inventory["scope"],
        "site_ranges": inventory["site_ranges"],
        "frontier": {
            "occurrences": inventory["frontier_occurrences"],
            "unique_raw_words": inventory["unique_raw_words"],
            "unique_vas": inventory["unique_vas"],
            "unique_va_records": inventory["unique_va_records"],
            "class_counts": inventory["class_counts"],
            "range_membership_label_counts": inventory["range_membership_label_counts"],
            "family_counts": inventory["family_counts"],
        },
        "accounting": inventory["accounting"],
        "decoder_extension_candidates": inventory["decoder_extension_candidates"],
        "decoder_extension_rank_basis": inventory["rank_basis"],
        "indirect_runtime_alias_site": inventory["indirect_runtime_alias_site"],
        "claims": {
            "PROVED": [
                "The exact XBL and exact Experiment 027 source/manifest pins were validated before the 027 decoder import.",
                "Only the 71 Experiment 027 INDIRECT_OR_UNSUPPORTED site ranges were scanned syntactically.",
                "Recognized-versus-unrecognized accounting and overlap deduplication are deterministic over those ranges.",
            ],
            "SUPPORTED": [],
            "HYPOTHESIS": [
                "Exact encoding-mask families are ranked as decoder-extension hypotheses; primary architecture-source and later semantic review remain required.",
            ],
            "REFUTED": [],
            "UNKNOWN": [
                "Range membership is not CFG reachability; no occurrence is claimed reachable or executable.",
                "Unknown raw forms remain UNKNOWN and no decoder safety or semantic extension is promoted.",
                "The retained indirect/runtime-alias site, runtime aliases, current destinations, execution order, and writer presence remain UNKNOWN.",
                "This inventory does not upgrade Experiment 027 and does not claim global consumer or writer absence.",
            ],
        },
        "boundary_bypass": {
            "status": "NOT_AUTHORIZED",
            "device": "none",
            "mmio": "none",
            "write": "none",
            "reason": "Host-only syntactic inventory; no activation or live authority.",
        },
        "reproducibility": {
            "generation_mode": "DETERMINISTIC_SORTED_JSON",
            "repetition_count": 2,
            "repetition_result": "BYTE_IDENTICAL",
            "publication": "O_EXCL_O_NOFOLLOW_MODE_0644",
        },
        "definition_of_done": definition_of_done_metadata(),
        "reproducible_command_template": "python3 tools/sm8150_dcb_unsupported_frontier.py --firmware-dir <exact-firmware-dir> --manifest-dir <public-manifest-dir> --output <public-manifest-path>",
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
    parser.add_argument("--tool", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir, args.manifest_dir, args.tool, args.manifest)
    encoded = (json.dumps(manifest, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
    write_no_clobber(args.output, encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
