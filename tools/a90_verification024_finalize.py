#!/usr/bin/env python3
"""Host-only Verification 024 evidence finalizer.

This module never imports a live transport and never contacts a device.  It
independently reads the fixed evidence roots, verifies stable no-follow input
files and their private hash bindings, and emits a small redacted manifest.
The finalizer is intentionally conservative: only a complete control/read /
reset / rollback / health chain can produce ``REFUSED_AT_MID``.  A returned
read value is always a potential security indicator, and every other missing
or malformed receipt is an incident rather than a negative result.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import struct
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from tools import a90_v024_control_retry as control_retry
    from tools import a90_v024_r2_incident as r2_incident
    from tools import a90_inline_remapper_mid_probe as inline_probe
    from tools.a90_last_kmsg_capture import parse_exact_reset_signature
    from tools.a90_inline_remapper_mid_probe import (
        fixed_op_argv,
        parse_fixed_op_result,
        parse_boot_id as inline_parse_boot_id,
        parse_cmdline as inline_parse_cmdline,
        parse_selftest as inline_parse_selftest,
        parse_toybox_payload as inline_parse_toybox_payload,
        parse_toybox_wc_count as inline_parse_toybox_wc_count,
        _parse_exact_lines as inline_parse_exact_lines,
        _parse_stat_identity as inline_parse_stat_identity,
        is_transport_no_value_payload as inline_is_transport_no_value_payload,
        protocol_terminal_and_tail_valid as inline_protocol_terminal_and_tail_valid,
        protocol_flags_for_argv as inline_protocol_flags_for_argv,
        protocol_expected_errno as inline_protocol_expected_errno,
        verify_flash_journal,
    )
    from tools.a90_acm_snapshot import BEGIN_RE, END_RE, parse_last_frame
    from tools.a90_autohud_arbitration import (
        STOPHUD_ARGV,
        STOPHUD_MAX_PAYLOAD_BYTES,
        STOPHUD_MAX_TRANSCRIPT_BYTES,
        validate_stophud_evidence_sizes,
        validate_stophud_payload,
    )
    from tools.a90_v024_physical_claim import (
        boot_prefix_claim_identity,
        boot_prefix_claim_path,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    import a90_v024_control_retry as control_retry  # type: ignore
    import a90_v024_r2_incident as r2_incident  # type: ignore
    import a90_inline_remapper_mid_probe as inline_probe  # type: ignore
    from a90_last_kmsg_capture import parse_exact_reset_signature  # type: ignore
    from a90_inline_remapper_mid_probe import (  # type: ignore
        fixed_op_argv,
        parse_fixed_op_result,
        parse_boot_id as inline_parse_boot_id,
        parse_cmdline as inline_parse_cmdline,
        parse_selftest as inline_parse_selftest,
        parse_toybox_payload as inline_parse_toybox_payload,
        parse_toybox_wc_count as inline_parse_toybox_wc_count,
        _parse_exact_lines as inline_parse_exact_lines,
        _parse_stat_identity as inline_parse_stat_identity,
        is_transport_no_value_payload as inline_is_transport_no_value_payload,
        protocol_terminal_and_tail_valid as inline_protocol_terminal_and_tail_valid,
        protocol_flags_for_argv as inline_protocol_flags_for_argv,
        protocol_expected_errno as inline_protocol_expected_errno,
        verify_flash_journal,
    )
    from a90_acm_snapshot import BEGIN_RE, END_RE, parse_last_frame  # type: ignore
    from a90_autohud_arbitration import (  # type: ignore
        STOPHUD_ARGV,
        STOPHUD_MAX_PAYLOAD_BYTES,
        STOPHUD_MAX_TRANSCRIPT_BYTES,
        validate_stophud_evidence_sizes,
        validate_stophud_payload,
    )
    from a90_v024_physical_claim import (  # type: ignore
        boot_prefix_claim_identity,
        boot_prefix_claim_path,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT_NAME = "evidence/private"
MANIFEST_ROOT_NAME = "evidence/manifests"
MAX_RECEIPT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
BOOT_PREFIX_SIZE = 60_882_944
# Linux assigns the block device number at boot. The finalizer must bind the
# value emitted by the fixed sda24 uevent to the temporary node it validates;
# a remembered major/minor pair is not an identity check. Keep only the
# bounded canonical-decimal grammar here and leave the actual value dynamic.
BOOT_MAJOR_MIN = 1
BOOT_MAJOR_MAX = 4095
BOOT_MINOR_MIN = 0
BOOT_MINOR_MAX = 1048575
_BOOT_UEVENT_STATIC_FIELDS = {
    "DEVNAME": "sda24",
    "DEVTYPE": "partition",
    "PARTN": "24",
    "PARTNAME": "boot",
}
_BOOT_ATTEST_NODE = "/tmp/a90-native/verification-024-sda24"
PARAM_CAPTURE_SIZE = 10 * 1024 * 1024
PARAM_PARTITION_SECTORS = 20_480
PARAM_PARTITION_BYTES = 10 * 1024 * 1024
PARAM_START_SECTOR = 125_080
PARAM_NODE_PATH = "/dev/sdm855_mblab_sda10"
PARAM_PARTNAME = "param"
PARAM_DEVNAME = "sda10"
PARAM_MAJOR = 8
PARAM_MINOR = 10
PARAM_LOGICAL_BLOCK_SIZE = 4096
PARAM_LOW_DEBUG_VALUE = "0x574f4c44"
PARAM_FORCE_UPLOAD_VALUE = "0x00000000"
PARAM_FMM_LOCK_VALUE = "0x00000000"
PARAM_DUMP_SINK_VALUE = "0x00000000"
PARAM_DEBUG_OFFSET = 0x900000
PARAM_FORCE_UPLOAD_OFFSET = 0x9003F4
PARAM_FMM_LOCK_OFFSET = 0x9003FC
PARAM_DUMP_SINK_OFFSET = 0x900400
PARAM_CMDLINE_UPLOAD_OFFSET = "9438196"
PARAM_RUNTIME = "v2321-usb-clean-identity-rodata"
READ_SOURCE_EXPERIMENT_ID = "verification-024-read"
READ_SOURCE_MANIFEST_NAME = f"{READ_SOURCE_EXPERIMENT_ID}.manifest.json"
READ_SOURCE_RAW_NAME = f"{READ_SOURCE_EXPERIMENT_ID}.json"
READ_SOURCE_JOURNAL_NAME = f"{READ_SOURCE_EXPERIMENT_ID}.journal.json"
# Every input in the V024 final chain has one owner-selected identity.  The
# control/read IDs are shared with the inline probe; the remaining IDs are
# the fixed final-chain producer slots.  Callers may patch REPO_ROOT for an
# isolated host fixture, but may not mint another evidence namespace or swap
# an arbitrary producer path into this chain.
# R2, R3, and R4 were consumed by preflight-only incidents and are retained as
# fixed, read-only incident checkpoints.  R5 is the only executable control
# owner; the original control ID remains the historical predecessor.
CONTROL_EXPERIMENT_ID = "verification-024-control-r5"
CONTROL_R2_EXPERIMENT_ID = "verification-024-control-r2"
CONTROL_R3_EXPERIMENT_ID = "verification-024-control-r3"
CONTROL_R4_EXPERIMENT_ID = "verification-024-control-r4"
CONTROL_PREDECESSOR_EXPERIMENT_ID = "verification-024-control"
CONTROL_MANIFEST_NAME = f"{CONTROL_EXPERIMENT_ID}.manifest.json"
CONTROL_R5_PRECLAIM_SCHEMA = "sdm855-a90-inline-remapper-mid-journal-v1"
CONTROL_R5_PRECLAIM_STATUS = "PREDECESSOR_VALIDATION_PENDING"
CONTROL_R2_PREDECESSOR_CAPSULE_SCHEMA = (
    "sdm855-a90-v024-control-predecessor-final-capsule-v1"
)
CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = (
    "56d233030e1c970b486721b21293a91a154bdc5ebe0ae811b36473457648df15"
)
CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = 4924
CONTROL_R5_HISTORICAL_PINS_POLICY = (
    "historical_predecessor_capsule_bound; current_r5_source_provenance_required_before_live"
)
# Compatibility names are kept for host fixtures and historical callers. They
# alias the active R5 preclaim values and do not make any consumed ID valid.
CONTROL_R4_PRECLAIM_SCHEMA = CONTROL_R5_PRECLAIM_SCHEMA
CONTROL_R4_PRECLAIM_STATUS = CONTROL_R5_PRECLAIM_STATUS
CONTROL_R4_HISTORICAL_PINS_POLICY = CONTROL_R5_HISTORICAL_PINS_POLICY
CONTROL_R3_PRECLAIM_SCHEMA = CONTROL_R5_PRECLAIM_SCHEMA
CONTROL_R3_PRECLAIM_STATUS = CONTROL_R5_PRECLAIM_STATUS
CONTROL_R3_HISTORICAL_PINS_POLICY = CONTROL_R5_HISTORICAL_PINS_POLICY
CONTROL_R2_PRECLAIM_SCHEMA = CONTROL_R5_PRECLAIM_SCHEMA
CONTROL_R2_PRECLAIM_STATUS = CONTROL_R5_PRECLAIM_STATUS
CONTROL_R2_HISTORICAL_PINS_POLICY = CONTROL_R5_HISTORICAL_PINS_POLICY
CONTROL_R2_INCIDENT_MANIFEST_SHA256 = r2_incident.INCIDENT_MANIFEST_SHA256
CONTROL_R2_INCIDENT_MANIFEST_SIZE = r2_incident.INCIDENT_MANIFEST_SIZE
CONTROL_R2_INCIDENT_VALIDATION_SCHEMA = r2_incident.VALIDATION_SCHEMA
CONTROL_R3_INCIDENT_MANIFEST_SHA256 = r2_incident.R3_INCIDENT_MANIFEST_SHA256
CONTROL_R3_INCIDENT_MANIFEST_SIZE = r2_incident.R3_INCIDENT_MANIFEST_SIZE
CONTROL_R3_INCIDENT_VALIDATION_SCHEMA = r2_incident.R3_VALIDATION_SCHEMA
CONTROL_R4_INCIDENT_MANIFEST_SHA256 = r2_incident.R4_INCIDENT_MANIFEST_SHA256
CONTROL_R4_INCIDENT_MANIFEST_SIZE = r2_incident.R4_INCIDENT_MANIFEST_SIZE
CONTROL_R4_INCIDENT_VALIDATION_SCHEMA = r2_incident.R4_VALIDATION_SCHEMA
LAST_KMSG_EXPERIMENT_ID = "last-kmsg-final"
LAST_KMSG_MANIFEST_NAME = f"{LAST_KMSG_EXPERIMENT_ID}.manifest.json"
STOPHUD_MAX_ATTEMPTS = 3
# The System-boot producer has one pre-registered V024 identity.  Keep this
# longer name fixed so a shorter caller-minted namespace cannot be spliced into
# the final chain.
ROLLBACK_SYSTEM_EXPERIMENT_ID = "verification-024-system-boot-rollback"
ROLLBACK_SYSTEM_JOURNAL_NAME = f"{ROLLBACK_SYSTEM_EXPERIMENT_ID}.journal.json"
PARAM_CAPTURE_EXPERIMENT_ID = "param-low"
PARAM_CAPTURE_MANIFEST_NAME = f"{PARAM_CAPTURE_EXPERIMENT_ID}.manifest.json"
RUNTIME_HEALTH_EXPERIMENT_ID = "runtime-health"
RUNTIME_HEALTH_MANIFEST_NAME = f"{RUNTIME_HEALTH_EXPERIMENT_ID}.manifest.json"
FINAL_EXPERIMENT_ID = "verification-024-final"
TORN_ROLLBACK_EXPERIMENT_ID = "torn-final"
# These six facts are an independent exact safety projection for the control
# receipt.  They are required as strict boolean ``False`` values in public,
# raw, and journal records and are never inferred from outcomes or frames.
CONTROL_SAFETY_EFFECT_FIELDS = (
    "memory_or_mmio_writes",
    "controller_writes",
    "smc",
    "protected_memory_read",
    "partition_writes",
    "reboot_dispatched",
)
CONTROL_SAFETY_EFFECT_PROJECTION = {
    field: False for field in CONTROL_SAFETY_EFFECT_FIELDS
}
_SYSTEM_PUBLIC_TOP_KEYS = frozenset(
    {
        "schema",
        "experiment_id",
        "phase",
        "started_utc",
        "completed_utc",
        "status",
        "classification",
        "target_verified",
        "target_evaluation",
        "target_model",
        "target_device",
        "target_serial_sha256",
        "twrp_version",
        "target",
        "expected_target",
        "preflight",
        "preparation",
        "effect",
        "physical_effect_claim",
        "observation",
        "partition_writes",
        "partition_write",
        "dispatch_count",
        "effect_dispatched_count",
        "preparation_verified",
        "effect_replayed",
        "raw_serial_omitted",
        "raw_commands_omitted",
        "raw_receipts_omitted",
        "other_adb_endpoints_untouched",
        "journal_sha256",
        "journal_size",
        "claims",
    }
)
_SYSTEM_PUBLIC_NESTED_KEYS = {
    "target": frozenset(
        {
            "model",
            "device",
            "twrp_version",
            "serial_sha256",
            "state",
            "boot_id_sha256",
            "status",
        }
    ),
    "expected_target": frozenset(
        {"model", "device", "twrp_version", "serial_sha256", "state"}
    ),
    "preflight": frozenset(
        {"target_verified", "tw_gui_done", "twrp_help_sha256"}
    ),
    "preparation": frozenset(
        {
            "command",
            "read_command",
            "expected_value",
            "write_count",
            "read_count",
            "verified",
            "sync_command",
            "sync_write_count",
            "sync_verified",
            "sync_receipt_sha256",
        }
    ),
    "effect": frozenset(
        {
            "command",
            "dispatch_count",
            "write_count",
            "effect_dispatched_count",
            "effect_replayed",
        }
    ),
    "physical_effect_claim": frozenset(
        {
            "claimed",
            "attempted",
            "key_sha256",
            "claim_sha256",
            "claim_size",
            "boot_id_sha256",
        }
    ),
    "observation": frozenset({"method", "timeout_sec", "disconnect_observed"}),
    "claims": frozenset({"PROVED", "NO_REPLAY"}),
}
FLASH_JOURNAL_NAMES = {
    "control": "verification-024-remapper-boot-flash-control.journal.json",
    "read": "verification-024-remapper-boot-flash-read.journal.json",
    "rollback": "verification-024-remapper-boot-flash-rollback.journal.json",
}
FLASH_REMOTE_STAGING = {
    "control": "/tmp/sdm855-remapper-boot.img",
    "read": "/tmp/sdm855-remapper-boot-read.img",
    "rollback": "/tmp/sdm855-remapper-boot-rollback.img",
}
ROLLBACK_ADB = "/usr/lib/android-sdk/platform-tools/adb"
BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
BOOT_ID_SUBSTRING_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
MAX_TRANSPORT_EVIDENCE_BYTES = 1024 * 1024
SEMANTIC_CLAIM_SCHEMA = "sdm855-a90-inline-op-semantic-claim-v1"
CONTROL_SHA256 = "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247"
READ_SHA256 = "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed"
ROLLBACK_SHA256 = "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb"
# This order is part of the producer protocol, not an unordered membership
# set.  Keep the canonical READ -> CONTROL sequence explicit so a future hash
# value change cannot silently redefine the source identity.
ROLLBACK_ALLOWED_PREDECESSORS = [READ_SHA256, CONTROL_SHA256]
# ``PARAM_LOW_SHA256`` predates the V024 stable-byte contract.  Keep it as a
# compatibility/provenance alias only: the finalizer never uses this value as
# an eligibility identity.  Eligibility is recomputed from the complete raw
# image below.
PARAM_LOW_FULL_SHA256 = "1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345"
PARAM_LOW_SHA256 = PARAM_LOW_FULL_SHA256
PARAM_STABLE_OFFSET = 1
PARAM_STABLE_END = PARAM_PARTITION_BYTES
PARAM_STABLE_SIZE = PARAM_STABLE_END - PARAM_STABLE_OFFSET
PARAM_STABLE_EXCLUDED_RANGES = ((0, 1),)
PARAM_VOLATILE_RANGES = PARAM_STABLE_EXCLUDED_RANGES
PARAM_STABLE_RANGES = ((PARAM_STABLE_OFFSET, PARAM_STABLE_END),)
PARAM_STABLE_RANGE = (PARAM_STABLE_OFFSET, PARAM_STABLE_END)
PARAM_STABLE_MASK = {
    "excluded_ranges": [[0, 1]],
    "stable_ranges": [[PARAM_STABLE_OFFSET, PARAM_STABLE_END]],
    "stable_size": PARAM_STABLE_SIZE,
}
PARAM_STABLE_LOW_SHA256 = "c0c7147418cf13145a44369a960c81647d347f317cb35baed1d85b286253c68a"
# Descriptive aliases mirror the capture producer's public vocabulary while
# keeping the historical full-image name above explicitly provenance-only.
STABLE_PARAM_OFFSET = PARAM_STABLE_OFFSET
STABLE_PARAM_SIZE = PARAM_STABLE_SIZE
STABLE_PARAM_RANGE = PARAM_STABLE_RANGE
STABLE_PARAM_MASK = PARAM_STABLE_MASK
STABLE_LOW_SHA256 = PARAM_STABLE_LOW_SHA256
TARGET_MODEL = "SM-A908N"
TARGET_DEVICE = "r3q"
TARGET_SOC = "SM8150"
TARGET_DMID = "SM-A908N/SM8150"
TARGET_RUNTIME = "0.9.285"
TARGET_RUNTIME_BUILD = "v2321-usb-clean-identity-rodata"
TARGET_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
TARGET_BOOTLOADER = "A908NKSU5EWA3"
TARGET_SERIAL_SHA256 = "7f6dd1b66bdac00e950f3ddb207b7d8b2fca6859c7cdff99a3b96607d111fe46"
V024_TEMP_PATHS_SHA256 = "b1be7ed6f731c0c301184ecb19d0142bea432c946b1fecdde852871bb104224e"
SELFTEST_EXPECTED = {"passed": 11, "warn": 1, "fail": 0, "entries": 12}
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
UTC_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00\Z"
)
MAX_PUBLICATION_DELAY = dt.timedelta(seconds=30)
# This is the complete private projection emitted by the inline probe's
# ``_transport_no_value_evidence`` helper.  Keep it closed: a caller must not
# be able to hide a terminal frame under a renamed/nested field or append a
# second partial representation that the validator happens to ignore.
_TRANSPORT_NO_VALUE_EVIDENCE_KEYS = frozenset(
    {
        "exception_type",
        "exception_text",
        "payload_base64",
        "payload_sha256",
        "payload_size",
        "transcript_base64",
        "transcript_sha256",
        "transcript_size",
        "begin",
        "end",
        "payload_bounded",
        "transcript_bounded",
        "evidence_id",
        "argv",
        "transport_no_value",
        "partial_evidence_present",
        "a90r_present",
        "bounded",
    }
)


def _fixed_op_buffer_hash() -> str:
    buffer = bytearray(0x58)
    struct.pack_into("<Q", buffer, 0, 0xA90C0DE5DEADBEEF)
    buffer[8] = 4
    return hashlib.sha256(buffer).hexdigest()


def _fixed_flash_effect_argv(profile: str) -> list[str]:
    try:
        staging = FLASH_REMOTE_STAGING[profile]
    except KeyError as exc:
        raise FinalizeError(f"unknown fixed flash profile: {profile}") from exc
    return [
        "dd",
        f"if={staging}",
        "of=/dev/block/sda24",
        "bs=4096",
        "count=14864",
        "conv=fsync",
    ]


def _validate_guarded_effect_receipt(
    value: object,
    *,
    profile: str,
    predecessor: str,
    label: str,
) -> Mapping[str, object]:
    """Validate the boot producer's returned guard/DD projection exactly."""

    if not isinstance(value, Mapping):
        raise FinalizeError(f"{label} guarded effect receipt is missing")
    if set(value) != {"schema", "guard", "dd_result", "write_count"}:
        raise FinalizeError(f"{label} guarded effect receipt fields are not exact")
    _require(value, "schema", "sdm855-a90-remapper-guarded-effect-v1", label)
    _require(value, "write_count", 1, label)
    guard = value.get("guard")
    dd_result = value.get("dd_result")
    if not isinstance(guard, Mapping) or not isinstance(dd_result, Mapping):
        raise FinalizeError(f"{label} guarded effect receipt sections are missing")
    expected_guard = {
        "current_sha256": predecessor,
        "current_size": str(BOOT_PREFIX_SIZE),
        "staging_sha256": {
            "control": CONTROL_SHA256,
            "read": READ_SHA256,
            "rollback": ROLLBACK_SHA256,
        }[profile],
        "staging_size": str(BOOT_PREFIX_SIZE),
    }
    if dict(guard) != expected_guard:
        raise FinalizeError(f"{label} guarded effect guard projection differs")
    if dict(dd_result) != {"rc": "0", "count": "14864"}:
        raise FinalizeError(f"{label} guarded effect result is not exact")
    return value


class FinalizeError(ValueError):
    """A receipt cannot satisfy the exact Verification 024 contract."""


def _reject_symlink_components(path: Path, label: str) -> None:
    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise FinalizeError(f"{label} component is a symlink: {cursor}")
        if cursor == anchor:
            break
        cursor = cursor.parent


def _path_under(path: Path, root: Path, label: str) -> Path:
    path = path if path.is_absolute() else Path.cwd() / path
    root = root if root.is_absolute() else Path.cwd() / root
    _reject_symlink_components(path, label)
    _reject_symlink_components(root, f"{label} root")
    resolved = path.resolve(strict=False)
    root_resolved = root.resolve(strict=False)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise FinalizeError(f"{label} is outside its evidence root") from exc
    return resolved


def _fixed_output_root(args: argparse.Namespace) -> Path:
    """Resolve the sole repository-owned evidence namespace.

    ``--output-root`` is intentionally not a production option.  A direct
    embedding caller can still add an attribute to a Namespace, so reject
    every non-equal value before creating output directories or opening any
    producer receipt.  Tests replace this module's ``REPO_ROOT`` with an
    isolated temporary repository.
    """

    _reject_symlink_components(REPO_ROOT, "evidence root")
    expected = REPO_ROOT.resolve()
    _reject_symlink_components(expected, "evidence root")
    if hasattr(args, "output_root"):
        supplied = getattr(args, "output_root")
        if supplied is None:
            raise FinalizeError(
                "output root selector is disabled; root is fixed to REPO_ROOT"
            )
        try:
            supplied_path = Path(supplied)
            _reject_symlink_components(supplied_path, "output root selector")
            supplied_resolved = supplied_path.resolve(strict=False)
        except (TypeError, ValueError, OSError) as exc:
            raise FinalizeError(
                "output root selector is disabled; root is fixed to REPO_ROOT"
            ) from exc
        if supplied_resolved != expected:
            raise FinalizeError(
                "output root selector is disabled; root is fixed to REPO_ROOT"
            )
    return expected


def _fixed_input_path(
    args: argparse.Namespace,
    name: str,
    expected: Path | tuple[Path, ...],
    *,
    root: Path,
) -> Path:
    """Accept only a canonical producer path under the fixed root."""

    supplied = getattr(args, name, None)
    if supplied is None:
        raise FinalizeError(
            f"missing required fixed receipt path --{name.replace('_', '-') }"
        )
    try:
        supplied_path = Path(supplied)
        if not supplied_path.is_absolute():
            supplied_path = root / supplied_path
        _reject_symlink_components(supplied_path, f"{name} selector")
        resolved = supplied_path.resolve(strict=False)
    except (TypeError, ValueError, OSError) as exc:
        raise FinalizeError(f"{name} selector is not a fixed producer path") from exc
    expected_paths = expected if isinstance(expected, tuple) else (expected,)
    canonical = tuple(item.resolve(strict=False) for item in expected_paths)
    if resolved not in canonical:
        raise FinalizeError(f"{name} selector is not a fixed producer path")
    return resolved


def _fixed_chain_inputs(args: argparse.Namespace, root: Path) -> dict[str, Path]:
    """Validate all input selectors before any receipt validator runs."""

    private = root / PRIVATE_ROOT_NAME
    manifests = root / MANIFEST_ROOT_NAME
    return {
        "control_manifest": _fixed_input_path(
            args,
            "control_manifest",
            manifests / CONTROL_MANIFEST_NAME,
            root=root,
        ),
        "read_manifest": _fixed_input_path(
            args,
            "read_manifest",
            manifests / READ_SOURCE_MANIFEST_NAME,
            root=root,
        ),
        "last_kmsg": _fixed_input_path(
            args,
            "last_kmsg",
            manifests / LAST_KMSG_MANIFEST_NAME,
            root=root,
        ),
        "rollback_flash": _fixed_input_path(
            args,
            "rollback_flash",
            (
                private / FLASH_JOURNAL_NAMES["rollback"],
                private / "verification-024-boot-torn-rollback-torn-final.journal.json",
            ),
            root=root,
        ),
        "rollback_system_boot": _fixed_input_path(
            args,
            "rollback_system_boot",
            private / ROLLBACK_SYSTEM_JOURNAL_NAME,
            root=root,
        ),
        "param_capture": _fixed_input_path(
            args,
            "param_capture",
            manifests / PARAM_CAPTURE_MANIFEST_NAME,
            root=root,
        ),
        "runtime_health": _fixed_input_path(
            args,
            "runtime_health",
            manifests / RUNTIME_HEALTH_MANIFEST_NAME,
            root=root,
        ),
    }


def _open_regular_nofollow(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    parts = absolute.parts
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    parent_fd = os.open(parts[0], directory_flags)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        leaf_flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            leaf_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            leaf_flags |= os.O_NOFOLLOW
        return os.open(parts[-1], leaf_flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _stable_bytes(path: Path, *, root: Path, label: str, max_bytes: int = MAX_RECEIPT_BYTES) -> bytes:
    checked = _path_under(path, root, label)
    try:
        fd = _open_regular_nofollow(checked)
    except OSError as exc:
        raise FinalizeError(f"{label} cannot be opened: {checked}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise FinalizeError(f"{label} is not a regular file")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise FinalizeError(f"{label} exceeds bounded size {max_bytes}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise FinalizeError(f"{label} exceeds bounded size {max_bytes}")
        after = os.fstat(fd)
        identity = lambda info: (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        if identity(before) != identity(after) or total != after.st_size:
            raise FinalizeError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FinalizeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise FinalizeError(f"non-finite JSON number: {value}")


def _json(path: Path, *, root: Path, label: str) -> tuple[dict[str, object], bytes, Path]:
    checked = _path_under(path, root, label)
    data = _stable_bytes(checked, root=root, label=label)
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except FinalizeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalizeError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise FinalizeError(f"{label} root is not an object")
    return value, data, checked


def _require(obj: Mapping[str, object], key: str, expected: object, label: str) -> None:
    actual = obj.get(key)
    if type(actual) is not type(expected) or actual != expected:
        raise FinalizeError(f"{label} field {key!r} is not exact")


def _validate_control_safety_effect_projection(
    public: Mapping[str, object],
    raw: Mapping[str, object],
    journal: Mapping[str, object],
) -> dict[str, bool]:
    """Require and cross-bind the exact non-effect control projection."""

    projections: list[tuple[str, dict[str, bool]]] = []
    for label, owner in (
        ("control manifest", public),
        ("control raw", raw),
        ("control journal", journal),
    ):
        projection: dict[str, bool] = {}
        for field in CONTROL_SAFETY_EFFECT_FIELDS:
            value = owner.get(field)
            if type(value) is not bool or value is not False:
                raise FinalizeError(
                    f"{label} safety-effect field {field!r} is not exact False"
                )
            projection[field] = value
        projections.append((label, projection))

    expected = projections[0][1]
    for label, projection in projections[1:]:
        for field, value in expected.items():
            if projection[field] != value:
                raise FinalizeError(f"{label} safety-effect field {field!r} differs")
    return dict(expected)


def _reject_public_raw_boot_ids(value: object, label: str) -> None:
    """Keep raw Recovery boot UUIDs private in public producer manifests."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if key == "boot_id":
                raise FinalizeError(f"{label} exposes private boot_id")
            _reject_public_raw_boot_ids(item, label)
    elif isinstance(value, list):
        for item in value:
            _reject_public_raw_boot_ids(item, label)
    elif isinstance(value, str) and BOOT_ID_SUBSTRING_RE.search(value) is not None:
        raise FinalizeError(f"{label} exposes a raw Recovery boot UUID")


def _validate_private_boot_id_receipt(
    target: Mapping[str, object], label: str
) -> str:
    """Bind a private target UUID to the producer's raw command receipt.

    ``a90_twrp_system_boot_once`` stores the command bytes (normally
    ``UUID + LF`` or ``UUID + CRLF``) privately and hashes the normalized UUID
    separately for public publication.  Validate both layers here: a copied
    summary UUID or a changed receipt cannot satisfy the Recovery boot join.
    """

    boot_id = target.get("boot_id")
    if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
        raise FinalizeError(f"{label} Recovery boot_id is missing or malformed")
    boot_id_sha256 = hashlib.sha256(boot_id.encode("ascii")).hexdigest()
    if target.get("boot_id_sha256") != boot_id_sha256:
        raise FinalizeError(f"{label} Recovery boot_id_sha256 is not bound to boot_id")
    receipt = target.get("boot_id_receipt")
    if not isinstance(receipt, Mapping) or set(receipt) != {
        "base64",
        "sha256",
        "size",
    }:
        raise FinalizeError(f"{label} Recovery boot_id_receipt fields are not exact")
    encoded = receipt.get("base64")
    digest = receipt.get("sha256")
    size = receipt.get("size")
    if (
        not isinstance(encoded, str)
        or len(encoded) > MAX_RECEIPT_BYTES * 2
        or not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        or type(size) is not int
        or size <= 0
        or size > MAX_RECEIPT_BYTES
    ):
        raise FinalizeError(f"{label} Recovery boot_id_receipt is malformed")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise FinalizeError(f"{label} Recovery boot_id_receipt base64 is malformed") from exc
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise FinalizeError(f"{label} Recovery boot_id_receipt hash/size is not exact")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise FinalizeError(f"{label} Recovery boot_id_receipt is not ASCII") from exc
    # The producer's boot parser accepts exactly UUID, UUID+LF, or
    # UUID+CRLF.  Do not reproduce a broad ``strip`` normalization here:
    # surrounding whitespace, double newlines, bare CR, NUL, and tabs would
    # otherwise let a copied receipt bind to a different semantic value.
    allowed_raw = {
        boot_id.encode("ascii"),
        boot_id.encode("ascii") + b"\n",
        boot_id.encode("ascii") + b"\r\n",
    }
    if raw not in allowed_raw or text.rstrip("\r\n") != boot_id:
        raise FinalizeError(f"{label} Recovery boot_id_receipt UUID differs")
    return boot_id


def _require_hash(value: object, expected: str, label: str) -> None:
    if value != expected or not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise FinalizeError(f"{label} hash is not exact")


def _require_size(value: object, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise FinalizeError(f"{label} size is not exact")


def _require_inline_target(target: object, label: str) -> Mapping[str, object]:
    if not isinstance(target, Mapping):
        raise FinalizeError(f"{label} target is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "soc_id": "339",
        "runtime_version": TARGET_RUNTIME,
        "runtime_build": TARGET_RUNTIME_BUILD,
        "kernel": TARGET_KERNEL,
        "bootloader": TARGET_BOOTLOADER,
        "debug_level": "0x494d",
        "force_upload": "0",
        "dump_sink": "0",
    }.items():
        _require(target, key, expected, label)
    return target


def _require_selftest(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FinalizeError(f"{label} selftest is missing")
    for key, expected in SELFTEST_EXPECTED.items():
        _require(value, key, expected, label)
    duration = value.get("duration")
    if type(duration) is not int or duration < 0:
        raise FinalizeError(f"{label} selftest duration is not exact")
    return value


def _utc(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise FinalizeError(f"{label} completion time is not exact UTC")
    try:
        fmt = (
            "%Y-%m-%dT%H:%M:%S.%f+00:00"
            if "." in value
            else "%Y-%m-%dT%H:%M:%S+00:00"
        )
        return dt.datetime.strptime(value, fmt).replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise FinalizeError(f"{label} completion time is invalid") from exc


def _experiment_id(obj: Mapping[str, object], label: str) -> str:
    value = obj.get("experiment_id")
    if not isinstance(value, str) or SAFE_ID_RE.fullmatch(value) is None:
        raise FinalizeError(f"{label} experiment_id is not exact")
    return value


def _receipt_hash(data: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _parse_canonical_devnum(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> str:
    """Validate one exact unsigned decimal Linux device-number field."""

    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise FinalizeError(f"{label} is not canonical unsigned decimal")
    number = int(value, 10)
    if not minimum <= number <= maximum:
        raise FinalizeError(f"{label} is outside the bounded device-number range")
    return value


def _validate_boot_uevent_mapping(
    value: object, label: str
) -> dict[str, str]:
    """Validate the fixed sda24 identity while keeping dev_t boot-dynamic."""

    if not isinstance(value, Mapping):
        raise FinalizeError(f"{label} uevent mapping is missing")
    if set(value) != {"MAJOR", "MINOR", *_BOOT_UEVENT_STATIC_FIELDS}:
        raise FinalizeError(f"{label} uevent fields are not exact")
    major = _parse_canonical_devnum(
        value.get("MAJOR"),
        f"{label} MAJOR",
        BOOT_MAJOR_MIN,
        BOOT_MAJOR_MAX,
    )
    minor = _parse_canonical_devnum(
        value.get("MINOR"),
        f"{label} MINOR",
        BOOT_MINOR_MIN,
        BOOT_MINOR_MAX,
    )
    for key, expected in _BOOT_UEVENT_STATIC_FIELDS.items():
        if value.get(key) != expected:
            raise FinalizeError(f"{label} {key} is not exact")
    return {
        "MAJOR": major,
        "MINOR": minor,
        **_BOOT_UEVENT_STATIC_FIELDS,
    }


def _validate_dynamic_mknod_argv(value: object, label: str) -> tuple[str, ...]:
    """Validate mknod syntax; its numbers are bound to the decoded uevent later."""

    if not isinstance(value, (list, tuple)) or len(value) != 4:
        raise FinalizeError(f"{label} mknod argv is not exact")
    argv = tuple(value)
    if argv[:2] != ("mknodb", _BOOT_ATTEST_NODE):
        raise FinalizeError(f"{label} mknod path/command is not exact")
    _parse_canonical_devnum(
        argv[2], f"{label} mknod major", BOOT_MAJOR_MIN, BOOT_MAJOR_MAX
    )
    _parse_canonical_devnum(
        argv[3], f"{label} mknod minor", BOOT_MINOR_MIN, BOOT_MINOR_MAX
    )
    return argv


def _validate_current_boot_attestation(
    value: object,
    expected_hash: str,
    label: str,
    *,
    require_paths: bool = True,
) -> Mapping[str, object]:
    """Require the complete sda24 prefix proof, including dynamic dev_t."""

    if not isinstance(value, Mapping):
        raise FinalizeError(f"{label} current_boot_attestation is missing")
    public_keys = frozenset(
        {
            "sysfs_root",
            "block_node",
            "bs",
            "count",
            "expected_size",
            "captured_size",
            "expected_sha256",
            "captured_sha256",
            "sectors",
            "ro",
            "hash_matches_candidate",
            "size_matches_candidate",
            "cleanup_ok",
            "sysfs_uevent",
            "stat",
        }
    )
    private_keys = public_keys | frozenset(
        {
            "attest_file",
            "attest_node",
            "binding_events",
            "binding_failure",
            "cleanup_error",
            "pre_cleanup_error",
        }
    )
    expected_keys = private_keys if require_paths else public_keys
    if frozenset(value) != expected_keys:
        kind = "private" if require_paths else "public"
        raise FinalizeError(
            f"{label} current_boot_attestation {kind} fields are not exact"
        )
    uevent = _validate_boot_uevent_mapping(
        value.get("sysfs_uevent"), f"{label} current boot"
    )
    expected: dict[str, object] = {
        "sysfs_root": "/sys/class/block/sda24",
        "block_node": "/dev/block/sda24",
        "bs": 4096,
        "count": 14864,
        "expected_size": BOOT_PREFIX_SIZE,
        "captured_size": BOOT_PREFIX_SIZE,
        "expected_sha256": expected_hash,
        "captured_sha256": expected_hash,
        "sectors": 131072,
        "ro": 0,
        "hash_matches_candidate": True,
        "size_matches_candidate": True,
        "cleanup_ok": True,
        "sysfs_uevent": uevent,
    }
    if require_paths:
        expected.update(
            {
                "attest_node": "/tmp/a90-native/verification-024-sda24",
                "attest_file": "/tmp/a90-native/verification-024-boot-prefix.bin",
            }
        )
    for key, expected_value in expected.items():
        _require(value, key, expected_value, label)
    stat_value = value.get("stat")
    if not isinstance(stat_value, Mapping):
        raise FinalizeError(f"{label} current_boot_attestation stat is missing")
    if set(stat_value) != {"mode", "uid", "gid", "size", "rdev"}:
        raise FinalizeError(f"{label} current boot stat fields are not exact")
    for key, expected_value in {
        "mode": "0600",
        "uid": "0",
        "gid": "0",
        "size": "0",
        "rdev": f"{uevent['MAJOR']}:{uevent['MINOR']}",
    }.items():
        _require(stat_value, key, expected_value, f"{label} current boot stat")
    if require_paths:
        _require(value, "binding_failure", False, label)
        _require(value, "pre_cleanup_error", None, label)
        _require(value, "cleanup_error", None, label)
        if not isinstance(value.get("binding_events"), list):
            raise FinalizeError(f"{label} current boot binding events are not a list")
    return value


def _validate_panic_frame_set(
    frames: object, label: str, *, restored: bool
) -> None:
    """Validate actual bounded A90P1 records for the panic transition."""

    # The native ``writefile`` helper emits a result payload even though the
    # command itself has no value to read back.  This is part of the producer
    # contract: the successful frame is exactly ``writefile: ok`` (13 bytes),
    # with no line terminator.  Keeping this separate from the readback lines
    # below prevents an empty or normalized payload from authorizing a write.
    panic_writefile_payload = b"writefile: ok"

    if not isinstance(frames, list):
        raise FinalizeError(f"{label} frames are missing")
    expected: dict[str, tuple[tuple[str, ...], bytes]] = {
        "panic_before": (("cat", "/proc/sys/kernel/panic_on_oops"), b"1\n"),
        "panic_set_0": (
            ("writefile", "/proc/sys/kernel/panic_on_oops", "0"),
            panic_writefile_payload,
        ),
        "panic_zero_verify": (("cat", "/proc/sys/kernel/panic_on_oops"), b"0\n"),
    }
    if restored:
        expected.update(
            {
                "panic_set_1": (
                    ("writefile", "/proc/sys/kernel/panic_on_oops", "1"),
                    panic_writefile_payload,
                ),
                "panic_restore_verify": (("cat", "/proc/sys/kernel/panic_on_oops"), b"1\n"),
            }
        )
    expected_ids = list(expected)
    observed_ids = [
        item.get("evidence_id")
        for item in frames
        if isinstance(item, Mapping)
        and item.get("evidence_id") in expected
    ]
    # The panic transition is a protocol sequence, not an unordered bag of
    # summaries.  In particular, a duplicate/renamed frame must not be able
    # to satisfy the three-frame refusal proof while moving a later state
    # read ahead of the zero write.
    if observed_ids != expected_ids:
        raise FinalizeError(f"{label} panic frame order/count is not exact")
    for evidence_id, (argv, expected_payload) in expected.items():
        matches = [
            item
            for item in frames
            if isinstance(item, Mapping) and item.get("evidence_id") == evidence_id
        ]
        if len(matches) != 1:
            raise FinalizeError(f"{label} requires exactly one {evidence_id} frame")
        frame = matches[0]
        _validate_protocol_frame(
            frame,
            evidence_id,
            argv,
            f"{label} {evidence_id}",
            expected_payload=expected_payload,
            exact_payload=evidence_id in {"panic_set_0", "panic_set_1"},
        )


def _reject_hidden_complete_fixed_op_frames(frames: object, label: str) -> None:
    """Compatibility name for the closed full-frame validator.

    Older callers used this helper as a substring scan and consequently
    rejected every valid ``A90P1 END`` line.  Keep the symbol for existing
    host tests, but perform only the allowlisted record/schema validation;
    complete END markers are expected in all retained frames.
    """

    _validate_frame_list(frames, label, restored=False, allow_fixed=False)


def _require_panic_frames_equal(
    raw_frames: object, journal_frames: object, label: str
) -> None:
    """Cross-bind the complete retained frame lists, not just summaries."""

    if not isinstance(raw_frames, list) or not isinstance(journal_frames, list):
        raise FinalizeError(f"{label} panic frame receipts are missing")
    if raw_frames != journal_frames:
        raise FinalizeError(f"{label} raw/journal frames differ")


def _validate_fixed_measurement(
    value: object, expected_value: str, label: str
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FinalizeError(f"{label} fixed-op measurement is missing")
    expected = {
        "op": 4,
        "args": [],
        "buffer_size": 0x58,
        "buffer_sha256": _fixed_op_buffer_hash(),
        "magic": "0xa90c0de5deadbeef",
        "rc": 0,
        "status": "ok",
        "value": expected_value,
    }
    for key, expected_value_item in expected.items():
        _require(value, key, expected_value_item, label)
    argv = value.get("argv")
    if argv != list(fixed_op_argv()):
        raise FinalizeError(f"{label} fixed-op argv is not the exact pinned helper")
    record = value.get("a90r_record")
    if not isinstance(record, str) or re.fullmatch(r"A90R[0-9a-f]{1,16}", record) is None:
        raise FinalizeError(f"{label} fixed-op A90R record is not exact")
    if record != f"A90R{int(expected_value, 16):x}":
        raise FinalizeError(f"{label} fixed-op A90R value differs")
    return value


_FIXED_OP_FRAME_KEYS = {
    "evidence_id",
    "argv",
    "payload_base64",
    "payload_sha256",
    "payload_size",
    "transcript_base64",
    "transcript_sha256",
    "transcript_size",
    "begin",
    "end",
}

# Every retained exchange emitted by the inline producer has this one closed
# shape.  Keeping the set closed is important: a renamed/extra frame cannot
# be ignored by selecting only the three panic records.  ``A90P1 END`` itself
# is expected in every complete frame, so validation is structural rather
# than a substring ban on that perfectly valid marker.
_PROTOCOL_FRAME_KEYS = frozenset(
    {
        "evidence_id",
        "argv",
        "payload_base64",
        "payload_sha256",
        "payload_size",
        "transcript_base64",
        "transcript_sha256",
        "transcript_size",
        "begin",
        "end",
    }
)
_FRAME_BEGIN_KEYS = frozenset({"cmd", "seq", "argc", "flags"})
_FRAME_END_KEYS = frozenset(
    {"cmd", "seq", "rc", "errno", "duration_ms", "flags", "status"}
)
_CANONICAL_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_CANONICAL_SIGNED_DECIMAL_RE = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")


def _payload_line_variants(expected: bytes) -> frozenset[bytes]:
    """Return only the producer's LF/CRLF terminal variants for one value."""

    if not expected:
        return frozenset({b""})
    if expected.endswith(b"\n"):
        stem = expected[:-1]
        return frozenset({stem + b"\n", stem + b"\r\n"})
    return frozenset({expected, expected + b"\n", expected + b"\r\n"})


def _validate_protocol_tail(
    transcript: bytes, end_match: re.Match[bytes], label: str
) -> None:
    """Permit only the native prompt after END, never arbitrary suffix bytes."""

    tail = transcript[end_match.end() :]
    if tail not in {
        b"",
        b"a90:/# ",
        b"a90:/# \n",
        b"a90:/# \r\n",
    }:
        raise FinalizeError(f"{label} transcript has an unexpected suffix")
_NEGATIVE_FRAME_ARGV: dict[str, tuple[str, ...]] = {
    "version_before": ("version",),
    "cmdline_before": ("cat", "/proc/cmdline"),
    "soc_id_before": ("cat", "/sys/devices/soc0/soc_id"),
    "selftest_before": ("selftest", "status"),
    "panic_before": ("cat", "/proc/sys/kernel/panic_on_oops"),
    "boot_id_before_read": (
        "cat",
        "/proc/sys/kernel/random/boot_id",
    ),
    "panic_set_0": ("writefile", "/proc/sys/kernel/panic_on_oops", "0"),
    "panic_zero_verify": ("cat", "/proc/sys/kernel/panic_on_oops"),
    "panic_set_1": ("writefile", "/proc/sys/kernel/panic_on_oops", "1"),
    "panic_restore_verify": ("cat", "/proc/sys/kernel/panic_on_oops"),
    "version_after": ("version",),
    "cmdline_after": ("cat", "/proc/cmdline"),
    "selftest_after": ("selftest", "status"),
    "soc_id_after": ("cat", "/sys/devices/soc0/soc_id"),
    "boot_sysfs_uevent": ("cat", "/sys/class/block/sda24/uevent"),
    "boot_sysfs_size": ("cat", "/sys/class/block/sda24/size"),
    "boot_sysfs_ro": ("cat", "/sys/class/block/sda24/ro"),
    "boot_attest_mkdir": (
        "run",
        "/bin/toybox",
        "mkdir",
        "-p",
        "/tmp/a90-native",
    ),
    "boot_attest_stat_node": (
        "stat",
        "/tmp/a90-native/verification-024-sda24",
    ),
    "boot_attest_capture": (
        "run",
        "/bin/toybox",
        "dd",
        "if=/tmp/a90-native/verification-024-sda24",
        "of=/tmp/a90-native/verification-024-boot-prefix.bin",
        "bs=4096",
        "count=14864",
        "conv=fsync",
        "status=none",
    ),
    "boot_attest_hash": (
        "run",
        "/bin/toybox",
        "sha256sum",
        "/tmp/a90-native/verification-024-boot-prefix.bin",
    ),
    "boot_attest_size": (
        "run",
        "/bin/toybox",
        "wc",
        "-c",
        "/tmp/a90-native/verification-024-boot-prefix.bin",
    ),
}
for _id, _path in (
    ("boot_attest_remove_node", "/tmp/a90-native/verification-024-sda24"),
    ("boot_attest_remove_file", "/tmp/a90-native/verification-024-boot-prefix.bin"),
    ("boot_attest_node_absent", "/tmp/a90-native/verification-024-sda24"),
    ("boot_attest_file_absent", "/tmp/a90-native/verification-024-boot-prefix.bin"),
    ("boot_attest_pre_node_absent", "/tmp/a90-native/verification-024-sda24"),
    ("boot_attest_pre_file_absent", "/tmp/a90-native/verification-024-boot-prefix.bin"),
):
    if _id.endswith("_not_symlink"):
        continue
    if "remove_" in _id:
        _NEGATIVE_FRAME_ARGV[_id] = ("run", "/bin/toybox", "rm", "-f", _path)
    else:
        _NEGATIVE_FRAME_ARGV[_id] = ("run", "/bin/toybox", "test", "!", "-e", _path)
        _NEGATIVE_FRAME_ARGV[_id + "_not_symlink"] = (
            "run",
            "/bin/toybox",
            "test",
            "!",
            "-L",
            _path,
        )


def _frame_expected_argv(evidence_id: object) -> tuple[str, ...] | None:
    if not isinstance(evidence_id, str):
        return None
    if re.fullmatch(r"stophud_[1-3]", evidence_id):
        return ("stophud",)
    if evidence_id == "fixed_op_4":
        return tuple(fixed_op_argv())
    return _NEGATIVE_FRAME_ARGV.get(evidence_id)


def _expected_full_frame_ids(
    stop_count: int,
    *,
    allow_fixed: bool,
    restored: bool,
    include_health: bool = False,
) -> list[str]:
    """Return the inline producer's complete successful exchange sequence."""

    if type(stop_count) is not int or stop_count < 1 or stop_count > 3:
        raise FinalizeError("inline stophud frame count is outside the fixed 1..3 bound")

    ids = [f"stophud_{index}" for index in range(1, stop_count + 1)]
    ids.extend(
        [
            "version_before",
            "cmdline_before",
            "soc_id_before",
            "selftest_before",
            "panic_before",
            "boot_attest_remove_node",
            "boot_attest_remove_file",
            "boot_attest_node_absent",
            "boot_attest_node_absent_not_symlink",
            "boot_attest_file_absent",
            "boot_attest_file_absent_not_symlink",
            "boot_attest_pre_node_absent",
            "boot_attest_pre_node_absent_not_symlink",
            "boot_attest_pre_file_absent",
            "boot_attest_pre_file_absent_not_symlink",
            "boot_sysfs_uevent",
            "boot_sysfs_size",
            "boot_sysfs_ro",
            "boot_attest_mkdir",
            "boot_attest_mknod",
            "boot_attest_stat_node",
            "boot_attest_capture",
            "boot_attest_hash",
            "boot_attest_size",
            "boot_attest_remove_node",
            "boot_attest_remove_file",
            "boot_attest_node_absent",
            "boot_attest_node_absent_not_symlink",
            "boot_attest_file_absent",
            "boot_attest_file_absent_not_symlink",
            "boot_id_before_read",
            "panic_set_0",
            "panic_zero_verify",
        ]
    )
    if allow_fixed:
        ids.append("fixed_op_4")
        if restored:
            ids.extend(["panic_set_1", "panic_restore_verify"])
            if include_health:
                ids.extend(
                    [
                        "version_after",
                        "cmdline_after",
                        "selftest_after",
                        "soc_id_after",
                    ]
                )
    return ids


def _decode_frame_bytes(
    encoded: object, size: object, digest: object, label: str
) -> bytes:
    if not isinstance(encoded, str) or len(encoded) > MAX_TRANSPORT_EVIDENCE_BYTES * 2:
        raise FinalizeError(f"{label} base64 is missing or oversized")
    if type(size) is not int or size < 0 or size > MAX_TRANSPORT_EVIDENCE_BYTES:
        raise FinalizeError(f"{label} size is not bounded")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise FinalizeError(f"{label} hash is malformed")
    try:
        decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise FinalizeError(f"{label} base64 is malformed") from exc
    if len(decoded) != size or hashlib.sha256(decoded).hexdigest() != digest:
        raise FinalizeError(f"{label} hash/size does not match bytes")
    return decoded


def _validate_protocol_frame(
    frame: object,
    evidence_id: str,
    argv: tuple[str, ...],
    label: str,
    *,
    expected_payload: bytes | None = None,
    exact_payload: bool = False,
    expected_rc: str = "0",
    expected_status: str = "ok",
) -> None:
    """Validate one complete producer frame including its transcript."""

    if not isinstance(frame, Mapping) or set(frame) != _PROTOCOL_FRAME_KEYS:
        raise FinalizeError(f"{label} frame fields are incomplete or forged")
    if frame.get("evidence_id") != evidence_id or frame.get("argv") != list(argv):
        raise FinalizeError(f"{label} evidence ID/argv is not exact")
    begin = frame.get("begin")
    end = frame.get("end")
    if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
        raise FinalizeError(f"{label} begin/end is missing")
    if set(begin) != _FRAME_BEGIN_KEYS or set(end) != _FRAME_END_KEYS:
        raise FinalizeError(f"{label} begin/end fields are not exact")
    sequence = begin.get("seq")
    if (
        begin.get("cmd") != argv[0]
        or end.get("cmd") != argv[0]
        or not isinstance(sequence, str)
        or _CANONICAL_DECIMAL_RE.fullmatch(sequence) is None
        or end.get("seq") != sequence
        or begin.get("argc") != str(len(argv))
        or begin.get("flags") != inline_protocol_flags_for_argv(argv)
        or end.get("rc") != expected_rc
        or not isinstance(end.get("errno"), str)
        or _CANONICAL_DECIMAL_RE.fullmatch(end.get("errno", "")) is None
        or end.get("errno") != inline_protocol_expected_errno(expected_rc)
        or not isinstance(end.get("duration_ms"), str)
        or _CANONICAL_DECIMAL_RE.fullmatch(end.get("duration_ms", "")) is None
        or end.get("flags") != inline_protocol_flags_for_argv(argv)
        or end.get("status") != expected_status
    ):
        raise FinalizeError(f"{label} begin/end sequence or terminal is not exact")
    payload = _decode_frame_bytes(
        frame.get("payload_base64"),
        frame.get("payload_size"),
        frame.get("payload_sha256"),
        f"{label} payload",
    )
    transcript = _decode_frame_bytes(
        frame.get("transcript_base64"),
        frame.get("transcript_size"),
        frame.get("transcript_sha256"),
        f"{label} transcript",
    )
    if argv == STOPHUD_ARGV:
        try:
            validate_stophud_evidence_sizes(payload, transcript)
        except BaseException as exc:
            raise FinalizeError(
                f"{label} stophud evidence size is not bounded"
            ) from exc
    if expected_payload is not None:
        if exact_payload:
            payload_matches = payload == expected_payload
        else:
            payload_matches = payload in _payload_line_variants(expected_payload)
        if not payload_matches:
            raise FinalizeError(f"{label} payload is not exact")
    begin_matches = list(BEGIN_RE.finditer(transcript))
    end_matches = list(END_RE.finditer(transcript))
    if (
        transcript.count(b"A90P1 BEGIN") != len(begin_matches)
        or transcript.count(b"A90P1 END") != len(end_matches)
        or len(begin_matches) != 1
        or len(end_matches) != 1
    ):
        raise FinalizeError(f"{label} transcript framing is not singular")
    try:
        parsed = parse_last_frame(transcript, argv[0])
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FinalizeError(f"{label} transcript is not complete") from exc
    if parsed.begin != dict(begin) or parsed.end != dict(end) or parsed.payload != payload:
        raise FinalizeError(f"{label} transcript does not bind begin/end/payload")
    begin_match = begin_matches[0]
    end_match = end_matches[0]
    if end_match.start() < begin_match.end():
        raise FinalizeError(f"{label} transcript boundaries are not ordered")
    _validate_protocol_tail(transcript, end_match, label)
    if not inline_protocol_terminal_and_tail_valid(
        transcript, begin_match, end_match, argv, end
    ):
        raise FinalizeError(f"{label} transcript terminal/tail is not exact")
    body = transcript[begin_match.end() : end_match.start()]
    terminals = list(
        re.finditer(
            rb"(?:^|\r?\n)\[(?P<kind>done|err|busy)\] [^\r\n]*(?:\r\n|\n|\Z)",
            body,
        )
    )
    expected_kind = (
        "busy"
        if expected_rc == "-16" and expected_status == "busy"
        else "done"
        if expected_rc == "0" and expected_status == "ok"
        else "err"
    )
    if len(terminals) != 1 or terminals[0].group("kind").decode("ascii") != expected_kind:
        raise FinalizeError(f"{label} transcript terminal marker is not bound")
    if evidence_id != "fixed_op_4" and (b"A90R" in payload or b"A90R" in transcript):
        raise FinalizeError(f"{label} contains a hidden fixed-op result")


def _validate_frame_list(
    frames: object,
    label: str,
    *,
    restored: bool,
    allow_fixed: bool,
    include_health: bool = False,
) -> None:
    """Validate the complete retained frame list, not a filtered subset."""

    if not isinstance(frames, list) or not frames:
        raise FinalizeError(f"{label} frames are missing")
    if not restored and any(
        isinstance(item, Mapping)
        and item.get("evidence_id") in {"panic_set_1", "panic_restore_verify"}
        for item in frames
    ):
        raise FinalizeError(f"{label} no-value frames contain a restore exchange")
    stop_ids = [
        item.get("evidence_id")
        for item in frames
        if isinstance(item, Mapping)
        and isinstance(item.get("evidence_id"), str)
        and re.fullmatch(r"stophud_[1-3]", item["evidence_id"])
    ]
    if stop_ids != [
        f"stophud_{index}" for index in range(1, len(stop_ids) + 1)
    ]:
        raise FinalizeError(f"{label} stophud frame IDs are not contiguous")
    if not 1 <= len(stop_ids) <= STOPHUD_MAX_ATTEMPTS:
        raise FinalizeError(f"{label} requires one to three stophud frames")
    counts: dict[str, int] = {}
    frame_ids = [
        item.get("evidence_id") if isinstance(item, Mapping) else None
        for item in frames
    ]
    stop_count = len(stop_ids)
    expected_ids = _expected_full_frame_ids(
        stop_count,
        allow_fixed=allow_fixed,
        restored=restored,
        include_health=include_health,
    )
    actual_ids = [item for item in frame_ids if isinstance(item, str)]
    if actual_ids != expected_ids:
        raise FinalizeError(f"{label} frame sequence contains extra or missing records")
    for index, frame in enumerate(frames):
        if not isinstance(frame, Mapping):
            raise FinalizeError(f"{label}[{index}] frame is not an object")
        evidence_id = frame.get("evidence_id")
        if evidence_id == "fixed_op_4" and not allow_fixed:
            raise FinalizeError(f"{label} no-value frames contain fixed_op_4")
        # The kernel may allocate a different block minor after a reboot.  The
        # mknod frame is therefore syntax-checked here and its exact numbers
        # are cross-bound to the preceding uevent payload by the semantic
        # validator below.  Every other frame retains the closed argv map.
        if evidence_id == "boot_attest_mknod":
            argv = _validate_dynamic_mknod_argv(
                frame.get("argv"), f"{label}[{index}]"
            )
        else:
            argv = _frame_expected_argv(evidence_id)
        if argv is None:
            raise FinalizeError(f"{label}[{index}] frame ID is not allowlisted")
        if not isinstance(evidence_id, str):
            raise FinalizeError(f"{label}[{index}] frame ID is malformed")
        counts[evidence_id] = counts.get(evidence_id, 0) + 1
        if counts[evidence_id] > (3 if evidence_id.startswith("stophud_") else 2 if evidence_id in {
            "boot_attest_remove_node",
            "boot_attest_remove_file",
            "boot_attest_node_absent",
            "boot_attest_node_absent_not_symlink",
            "boot_attest_file_absent",
            "boot_attest_file_absent_not_symlink",
        } else 1):
            raise FinalizeError(f"{label} frame ID {evidence_id!r} is duplicated")
        expected_rc = "0"
        expected_status = "ok"
        if evidence_id.startswith("stophud_"):
            try:
                attempt = int(evidence_id.rsplit("_", 1)[1])
            except ValueError as exc:
                raise FinalizeError(f"{label} stophud frame ID is malformed") from exc
            stophud_ids = [
                item.get("evidence_id")
                for item in frames
                if isinstance(item, Mapping)
                and isinstance(item.get("evidence_id"), str)
                and item.get("evidence_id", "").startswith("stophud_")
            ]
            if attempt > len(stophud_ids):
                raise FinalizeError(f"{label} stophud frame sequence is not contiguous")
            expected_rc = "-16" if attempt < len(stophud_ids) else "0"
            expected_status = "busy" if attempt < len(stophud_ids) else "ok"
        _validate_protocol_frame(
            frame,
            evidence_id,
            argv,
            f"{label}[{index}]",
            expected_rc=expected_rc,
            expected_status=expected_status,
        )
        if evidence_id.startswith("stophud_"):
            stop_payload = _decode_frame_bytes(
                frame.get("payload_base64"),
                frame.get("payload_size"),
                frame.get("payload_sha256"),
                f"{label}[{index}] stophud payload",
            )
            try:
                validate_stophud_payload(
                    stop_payload, int(expected_rc, 10), expected_status
                )
            except BaseException as exc:
                raise FinalizeError(
                    f"{label}[{index}] stophud payload is not canonical"
                ) from exc
    _validate_panic_frame_set(frames, label, restored=restored)


def _semantic_single_line(payload: bytes, label: str) -> str:
    """Decode one producer line with only LF/CRLF terminal framing."""

    if b"\r" in payload.replace(b"\r\n", b""):
        raise FinalizeError(f"{label} contains a bare CR")
    if payload.endswith(b"\r\n"):
        body = payload[:-2]
    elif payload.endswith(b"\n"):
        body = payload[:-1]
    else:
        body = payload
    if not body or b"\n" in body or b"\r" in body or body[:1] in b" \t" or body[-1:] in b" \t":
        raise FinalizeError(f"{label} is not one exact line")
    try:
        return body.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise FinalizeError(f"{label} is not ASCII") from exc


def _semantic_lines(payload: bytes, label: str) -> list[str]:
    """Decode a producer payload with optional single LF/CRLF termination.

    ``parse_last_frame`` removes the protocol result delimiter before handing
    the payload to semantic validators.  Consequently a native command's
    final line may be retained either without a line ending or with exactly
    one LF/CRLF.  Keep the internal grammar closed: bare CR, NUL, empty
    records, and a second terminal newline are never normalized away.
    """

    if b"\r" in payload.replace(b"\r\n", b""):
        raise FinalizeError(f"{label} contains a bare CR")
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized.endswith(b"\n"):
        body = normalized[:-1]
    else:
        body = normalized
    if not body or body.endswith(b"\n") or b"\x00" in body:
        raise FinalizeError(f"{label} has empty or duplicate lines")
    try:
        lines = body.decode("ascii", errors="strict").split("\n")
    except UnicodeDecodeError as exc:
        raise FinalizeError(f"{label} is not ASCII") from exc
    if any(not line for line in lines):
        raise FinalizeError(f"{label} has empty internal lines")
    return lines


_SEMANTIC_DUPLICATE_FRAME_IDS = frozenset(
    {
        "boot_attest_remove_node",
        "boot_attest_remove_file",
        "boot_attest_node_absent",
        "boot_attest_node_absent_not_symlink",
        "boot_attest_file_absent",
        "boot_attest_file_absent_not_symlink",
    }
)


def _semantic_frame_payloads(frames: object, label: str) -> list[tuple[str, bytes]]:
    """Decode payloads in retained order, preserving duplicate occurrences."""

    if not isinstance(frames, list):
        raise FinalizeError(f"{label} frames are missing")
    result: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for index, frame in enumerate(frames):
        if not isinstance(frame, Mapping) or not isinstance(frame.get("evidence_id"), str):
            raise FinalizeError(f"{label}[{index}] frame identity is malformed")
        evidence_id = frame["evidence_id"]
        payload = _decode_frame_bytes(
            frame.get("payload_base64"),
            frame.get("payload_size"),
            frame.get("payload_sha256"),
            f"{label} {evidence_id} payload",
        )
        if evidence_id in seen and evidence_id not in _SEMANTIC_DUPLICATE_FRAME_IDS:
            raise FinalizeError(f"{label} duplicate {evidence_id!r} payloads differ")
        seen.add(evidence_id)
        result.append((evidence_id, payload))
    return result


_V024_DISPLAY_RE = re.compile(
    r"display: [0-9]+x[0-9]+"
    r"(?: connector=[0-9]+)?(?: crtc=[0-9]+)?(?: fb=[0-9]+)?\Z"
)


def _parse_v024_version_payload(payload: bytes, label: str) -> dict[str, str]:
    """Parse the retained V2321 version record and its bounded metadata."""

    if b"\r" in payload.replace(b"\r\n", b""):
        raise FinalizeError(f"{label} version payload contains a bare CR")
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized.endswith(b"\n"):
        normalized = normalized[:-1]
    if not normalized or b"\n\n" in normalized or b"\x00" in normalized:
        raise FinalizeError(f"{label} version payload has empty framing")
    try:
        lines = normalized.decode("ascii", errors="strict").split("\n")
    except UnicodeDecodeError as exc:
        raise FinalizeError(f"{label} version payload is not ASCII") from exc
    if any(not line for line in lines):
        raise FinalizeError(f"{label} version payload has an empty line")
    expected = [
        f"A90 Linux init {TARGET_RUNTIME} ({TARGET_RUNTIME_BUILD})",
        f"version: {TARGET_RUNTIME} build={TARGET_RUNTIME_BUILD}",
        f"kernel: {TARGET_KERNEL}",
    ]
    identity = [
        line
        for line in lines
        if line.startswith(("A90 Linux init ", "version: ", "kernel: "))
    ]
    if identity != expected:
        raise FinalizeError(f"{label} version identity lines are missing, conflicting, or reordered")
    owner_count = sum(line == "made by device owner" for line in lines)
    display_lines = [line for line in lines if line.startswith("display: ")]
    if owner_count > 1 or len(display_lines) > 1:
        raise FinalizeError(f"{label} version metadata is duplicated")
    for line in lines:
        if line in expected or line == "made by device owner":
            continue
        if _V024_DISPLAY_RE.fullmatch(line) is None:
            raise FinalizeError(f"{label} version metadata line is not exact")
    return {
        "runtime_version": TARGET_RUNTIME,
        "runtime_build": TARGET_RUNTIME_BUILD,
        "kernel": TARGET_KERNEL,
    }


def _semantic_version_payload(payload: bytes, label: str) -> Mapping[str, str]:
    return _parse_v024_version_payload(payload, label)


def _semantic_cmdline_payload(
    payload: bytes, target: Mapping[str, object], label: str
) -> Mapping[str, str]:
    try:
        parsed = inline_parse_cmdline(payload)
    except BaseException as exc:
        raise FinalizeError(f"{label} cmdline payload is malformed") from exc
    expected = {
        "androidboot.em.model": TARGET_MODEL,
        "androidboot.bootloader": TARGET_BOOTLOADER,
        "androidboot.debug_level": "0x494d",
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
    }
    for key, expected_value in expected.items():
        if parsed.get(key) != expected_value:
            raise FinalizeError(f"{label} cmdline {key} is not exact")
    if target.get("model") != parsed.get("androidboot.em.model"):
        raise FinalizeError(f"{label} cmdline model differs from target")
    if target.get("bootloader") != parsed.get("androidboot.bootloader"):
        raise FinalizeError(f"{label} cmdline bootloader differs from target")
    if target.get("debug_level") != parsed.get("androidboot.debug_level"):
        raise FinalizeError(f"{label} cmdline debug level differs from target")
    if target.get("force_upload") not in {"0", parsed.get("androidboot.force_upload")}:
        raise FinalizeError(f"{label} cmdline force-upload differs from target")
    if target.get("dump_sink") not in {"0", parsed.get("sec_debug.dump_sink")}:
        raise FinalizeError(f"{label} cmdline dump-sink differs from target")
    return parsed


def _bind_v024_version_identity(
    identity: Mapping[str, str], target: Mapping[str, object], label: str
) -> None:
    for key in ("runtime_version", "runtime_build", "kernel"):
        if target.get(key) != identity.get(key):
            raise FinalizeError(f"{label} version {key} differs from target")


def _semantic_uevent_payload(payload: bytes, label: str) -> dict[str, str]:
    lines = _semantic_lines(payload, label)
    parsed: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            raise FinalizeError(f"{label} uevent payload has a malformed line")
        key, value = line.split("=", 1)
        if not key or not value or key in parsed:
            raise FinalizeError(f"{label} uevent payload has duplicate/malformed fields")
        parsed[key] = value
    return _validate_boot_uevent_mapping(parsed, label)


def _semantic_toybox_body(payload: bytes, label: str) -> bytes:
    try:
        return inline_parse_toybox_payload(payload, label)
    except BaseException as exc:
        raise FinalizeError(f"{label} toybox wrapper is not one run/exit-0 record") from exc


def _semantic_selftest(payload: bytes, label: str) -> Mapping[str, int]:
    lines = _semantic_lines(payload, label)
    if len(lines) != 1:
        raise FinalizeError(f"{label} selftest has extra or missing records")
    if re.fullmatch(
        r"selftest: pass=[0-9]+ warn=[0-9]+ fail=[0-9]+ duration=[0-9]+ms entries=[0-9]+",
        lines[0],
    ) is None:
        raise FinalizeError(f"{label} selftest framing is not exact")
    try:
        parsed = inline_parse_selftest(payload, label)
    except BaseException as exc:
        raise FinalizeError(f"{label} selftest values are not exact") from exc
    return parsed


def _validate_inline_frame_payload_semantics(
    frames: object,
    *,
    target: Mapping[str, object],
    attestation: Mapping[str, object],
    candidate_sha256: str,
    candidate_size: int,
    boot_id_before_read: str,
    label: str,
    include_health: bool,
    health_target: Mapping[str, object] | None = None,
    health_selftest: Mapping[str, object] | None = None,
) -> None:
    """Bind every retained inline payload to the fact it is meant to prove."""

    ordered_payloads = _semantic_frame_payloads(frames, label)
    payloads: dict[str, bytes] = {}
    stop_ids = [
        evidence_id
        for evidence_id, _payload in ordered_payloads
        if evidence_id.startswith("stophud_")
    ]
    for evidence_id, payload in ordered_payloads:
        # Unique records are addressed by ID below, while cleanup records are
        # intentionally retained as ordered occurrences.  Their run-wrapper
        # PID is dynamic per dispatch and must be checked independently.
        payloads.setdefault(evidence_id, payload)
        if evidence_id.startswith("stophud_"):
            attempt = int(evidence_id.rsplit("_", 1)[1])
            expected_rc = -16 if attempt < len(stop_ids) else 0
            expected_status = "busy" if attempt < len(stop_ids) else "ok"
            try:
                validate_stophud_payload(payload, expected_rc, expected_status)
            except BaseException as exc:
                raise FinalizeError(
                    f"{label} {evidence_id} stophud payload is not canonical"
                ) from exc

    version_identity = _semantic_version_payload(
        payloads["version_before"], f"{label} version_before"
    )
    _bind_v024_version_identity(version_identity, target, f"{label} version_before")
    before_cmdline = _semantic_cmdline_payload(
        payloads["cmdline_before"], target, f"{label} cmdline_before"
    )
    before_soc = _semantic_single_line(
        payloads["soc_id_before"], f"{label} soc_id_before"
    )
    if before_soc != "339":
        raise FinalizeError(f"{label} soc_id_before is not 339")
    if _semantic_single_line(payloads["boot_id_before_read"], f"{label} boot_id_before_read") != boot_id_before_read:
        raise FinalizeError(f"{label} boot_id_before_read differs from bound boot")
    decoded_selftest = _semantic_selftest(payloads["selftest_before"], f"{label} selftest_before")
    expected_selftest = target.get("selftest_before")
    if not isinstance(expected_selftest, Mapping) or dict(decoded_selftest) != dict(expected_selftest):
        raise FinalizeError(f"{label} selftest_before differs from target summary")

    uevent = _semantic_uevent_payload(payloads["boot_sysfs_uevent"], f"{label} boot_sysfs_uevent")
    if str(attestation.get("sectors")) != _semantic_single_line(payloads["boot_sysfs_size"], f"{label} boot_sysfs_size"):
        raise FinalizeError(f"{label} boot sysfs size differs from attestation")
    if str(attestation.get("ro")) != _semantic_single_line(payloads["boot_sysfs_ro"], f"{label} boot_sysfs_ro"):
        raise FinalizeError(f"{label} boot sysfs ro differs from attestation")
    if attestation.get("sectors") != 131072 or attestation.get("ro") != 0:
        raise FinalizeError(f"{label} attestation partition geometry is not exact")
    if attestation.get("sysfs_uevent") != uevent:
        raise FinalizeError(f"{label} boot sysfs uevent differs from attestation")
    mknod_frames = [
        frame
        for frame in frames
        if isinstance(frame, Mapping)
        and frame.get("evidence_id") == "boot_attest_mknod"
    ]
    if len(mknod_frames) != 1:
        raise FinalizeError(f"{label} boot_attest_mknod frame count is not exact")
    mknod_argv = _validate_dynamic_mknod_argv(
        mknod_frames[0].get("argv"), f"{label} boot_attest_mknod"
    )
    if mknod_argv[2:] != (uevent["MAJOR"], uevent["MINOR"]):
        raise FinalizeError(f"{label} mknod dev_t differs from boot uevent")
    try:
        stat_value = inline_parse_stat_identity(
            payloads["boot_attest_stat_node"],
            uevent["MAJOR"],
            uevent["MINOR"],
        )
    except BaseException as exc:
        raise FinalizeError(f"{label} boot_attest_stat_node payload is malformed") from exc
    expected_stat = {
        "mode": "0600",
        "uid": "0",
        "gid": "0",
        "size": "0",
        "rdev": f"{uevent['MAJOR']}:{uevent['MINOR']}",
    }
    if stat_value != expected_stat:
        raise FinalizeError(f"{label} boot_attest_stat_node differs from attestation")
    if attestation.get("stat") != stat_value:
        raise FinalizeError(f"{label} boot stat differs from attestation")

    for evidence_id, payload in ordered_payloads:
        if evidence_id in _SEMANTIC_DUPLICATE_FRAME_IDS:
            if _semantic_toybox_body(payload, f"{label} {evidence_id}") != b"":
                raise FinalizeError(f"{label} {evidence_id} has an unexpected command body")
    for evidence_id in ("boot_attest_mkdir", "boot_attest_capture"):
        if _semantic_toybox_body(payloads[evidence_id], f"{label} {evidence_id}") != b"":
            raise FinalizeError(f"{label} {evidence_id} has an unexpected command body")
    if payloads["boot_attest_mknod"] != b"":
        raise FinalizeError(f"{label} boot_attest_mknod must have an empty payload")
    hash_body = _semantic_toybox_body(payloads["boot_attest_hash"], f"{label} boot_attest_hash")
    if hash_body != f"{candidate_sha256}  /tmp/a90-native/verification-024-boot-prefix.bin".encode("ascii"):
        raise FinalizeError(f"{label} boot hash body differs from candidate")
    size_body = _semantic_toybox_body(payloads["boot_attest_size"], f"{label} boot_attest_size")
    expected_size_body = f"{candidate_size} /tmp/a90-native/verification-024-boot-prefix.bin".encode("ascii")
    if size_body != expected_size_body or attestation.get("captured_size") != candidate_size:
        raise FinalizeError(f"{label} captured size differs from candidate/attestation")
    if attestation.get("expected_sha256") != candidate_sha256 or attestation.get("captured_sha256") != candidate_sha256:
        raise FinalizeError(f"{label} captured hash differs from candidate/attestation")
    if attestation.get("expected_size") != candidate_size or attestation.get("captured_size") != candidate_size:
        raise FinalizeError(f"{label} captured size differs from candidate/attestation")

    if include_health:
        if health_target is None or health_selftest is None:
            raise FinalizeError(f"{label} final health facts are missing")
        final_version_identity = _semantic_version_payload(
            payloads["version_after"], f"{label} version_after"
        )
        _bind_v024_version_identity(
            final_version_identity, health_target, f"{label} version_after"
        )
        after_cmdline = _semantic_cmdline_payload(
            payloads["cmdline_after"], health_target, f"{label} cmdline_after"
        )
        after_soc = _semantic_single_line(
            payloads["soc_id_after"], f"{label} soc_id_after"
        )
        if after_soc != "339":
            raise FinalizeError(f"{label} soc_id_after is not 339")
        final_selftest = _semantic_selftest(payloads["selftest_after"], f"{label} selftest_after")
        if dict(final_selftest) != dict(health_selftest):
            raise FinalizeError(f"{label} selftest_after differs from health summary")
        if final_version_identity != version_identity:
            raise FinalizeError(f"{label} version_after semantic identity differs from pre-target health")
        if dict(after_cmdline) != dict(before_cmdline):
            raise FinalizeError(f"{label} cmdline_after semantic values differ from pre-target health")
        if after_soc != before_soc:
            raise FinalizeError(f"{label} soc_id_after differs from pre-target health")
        stable_selftest_fields = ("passed", "warn", "fail", "entries")
        if any(
            final_selftest[field] != decoded_selftest[field]
            for field in stable_selftest_fields
        ):
            raise FinalizeError(f"{label} selftest_after stable values differ from pre-target health")


def _validate_fixed_op_frame(
    frames: object,
    expected_value: str,
    label: str,
) -> Mapping[str, object]:
    """Validate the complete returned fixed-op frame, not its summaries.

    The fixed measurement is deliberately a secondary projection.  A public
    ``value``/``a90r_record`` field is not evidence of a returned operation
    unless one and only one retained A90P1 frame carries the exact pinned
    argv, matching BEGIN/END, bounded payload and transcript, and the
    canonical A90R line produced by the payload parser.
    """

    if not isinstance(frames, list):
        raise FinalizeError(f"{label} frames are missing")
    matches = [
        item
        for item in frames
        if isinstance(item, Mapping) and item.get("evidence_id") == "fixed_op_4"
    ]
    if len(matches) != 1:
        raise FinalizeError(f"{label} requires exactly one fixed_op_4 frame")
    frame = matches[0]
    if set(frame) != _FIXED_OP_FRAME_KEYS:
        raise FinalizeError(f"{label} fixed_op_4 frame fields are incomplete or forged")
    argv = frame.get("argv")
    expected_argv = list(fixed_op_argv())
    if argv != expected_argv:
        raise FinalizeError(f"{label} fixed_op_4 argv is not the pinned helper")
    begin = frame.get("begin")
    end = frame.get("end")
    if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
        raise FinalizeError(f"{label} fixed_op_4 boundaries are missing")
    if set(begin) != _FRAME_BEGIN_KEYS or set(end) != _FRAME_END_KEYS:
        raise FinalizeError(f"{label} fixed_op_4 boundary fields are forged")
    begin_seq = begin.get("seq")
    if (
        begin.get("cmd") != expected_argv[0]
        or end.get("cmd") != expected_argv[0]
        or not isinstance(begin_seq, str)
        or _CANONICAL_DECIMAL_RE.fullmatch(begin_seq) is None
        or end.get("seq") != begin_seq
        or begin.get("argc") != str(len(expected_argv))
        or begin.get("flags") != inline_protocol_flags_for_argv(expected_argv)
        or end.get("rc") != "0"
        or end.get("errno") != "0"
        or not isinstance(end.get("duration_ms"), str)
        or _CANONICAL_DECIMAL_RE.fullmatch(end.get("duration_ms", "")) is None
        or end.get("flags") != inline_protocol_flags_for_argv(expected_argv)
        or end.get("status") != "ok"
    ):
        raise FinalizeError(f"{label} fixed_op_4 boundary/terminal is not exact")
    payload_encoded = frame.get("payload_base64")
    transcript_encoded = frame.get("transcript_base64")
    payload = _decode_bounded_base64(
        payload_encoded, frame.get("payload_size"), frame.get("payload_sha256"),
        f"{label} fixed_op_4 payload",
    )
    transcript = _decode_bounded_base64(
        transcript_encoded,
        frame.get("transcript_size"),
        frame.get("transcript_sha256"),
        f"{label} fixed_op_4 transcript",
    )
    if not payload or not transcript:
        raise FinalizeError(f"{label} fixed_op_4 payload/transcript is empty")
    if len(BEGIN_RE.findall(transcript)) != 1 or len(END_RE.findall(transcript)) != 1:
        raise FinalizeError(f"{label} fixed_op_4 transcript framing is not singular")
    try:
        parsed = parse_last_frame(transcript, expected_argv[0])
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FinalizeError(f"{label} fixed_op_4 transcript is not complete") from exc
    if parsed.begin != dict(begin) or parsed.end != dict(end) or parsed.payload != payload:
        raise FinalizeError(f"{label} fixed_op_4 transcript does not bind frame")
    begin_match = next(BEGIN_RE.finditer(transcript), None)
    end_match = next(END_RE.finditer(transcript), None)
    if begin_match is None or end_match is None or end_match.start() < begin_match.end():
        raise FinalizeError(f"{label} fixed_op_4 transcript boundaries are not ordered")
    _validate_protocol_tail(transcript, end_match, label)
    if not inline_protocol_terminal_and_tail_valid(
        transcript, begin_match, end_match, expected_argv, end
    ):
        raise FinalizeError(f"{label} fixed_op_4 terminal/tail is not exact")
    body = transcript[begin_match.end() : end_match.start()]
    terminals = list(
        re.finditer(rb"(?:^|\r?\n)\[(?P<kind>done|err|busy)\] [^\r\n]*(?:\r\n|\n|\Z)", body)
    )
    if len(terminals) != 1 or terminals[0].group("kind") != b"done":
        raise FinalizeError(f"{label} fixed_op_4 transcript terminal is not [done]")
    # parse_fixed_op_result enforces the native toybox run banner, one exact
    # child exit-0 marker, and one complete canonical A90R line.  Calling it
    # on the independently decoded payload prevents a copied measurement
    # summary from manufacturing a returned value.
    try:
        parsed_value, parsed_record = parse_fixed_op_result(payload)
    except BaseException as exc:
        raise FinalizeError(f"{label} fixed_op_4 payload result is not exact") from exc
    expected_numeric = int(expected_value, 16)
    if parsed_value != expected_numeric or parsed_record != f"A90R{expected_numeric:x}":
        raise FinalizeError(f"{label} fixed_op_4 payload value differs")
    if transcript.count(b"A90R") != 1:
        raise FinalizeError(f"{label} fixed_op_4 transcript has extra A90R data")
    return frame


def _decode_bounded_base64(
    encoded: object,
    size: object,
    digest: object,
    label: str,
) -> bytes:
    if not isinstance(encoded, str) or len(encoded) > MAX_TRANSPORT_EVIDENCE_BYTES * 2:
        raise FinalizeError(f"{label} base64 is missing or oversized")
    if type(size) is not int or size <= 0 or size > MAX_TRANSPORT_EVIDENCE_BYTES:
        raise FinalizeError(f"{label} size is not bounded")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise FinalizeError(f"{label} hash is malformed")
    try:
        decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise FinalizeError(f"{label} base64 is malformed") from exc
    if len(decoded) != size or hashlib.sha256(decoded).hexdigest() != digest:
        raise FinalizeError(f"{label} hash/size does not match bytes")
    return decoded


def _validate_partial_begin_binding(
    value: Mapping[str, object], transcript: bytes | None, argv: list[str], label: str
) -> None:
    """Bind optional retained BEGIN metadata to the partial transcript.

    A no-value receipt may end before a terminal END frame, but it cannot
    carry a fabricated ``begin`` summary.  If a BEGIN was observed, it must
    be the one canonical ``run`` exchange and its sequence/argc must match
    both the retained mapping and the transcript bytes.
    """

    begin = value.get("begin")
    if transcript is None:
        if begin is not None:
            raise FinalizeError(f"{label} begin is present without a transcript")
        return
    begin_matches = list(BEGIN_RE.finditer(transcript))
    end_matches = list(END_RE.finditer(transcript))
    if transcript.count(b"A90P1 BEGIN") != len(begin_matches):
        raise FinalizeError(f"{label} transcript has malformed BEGIN framing")
    if transcript.count(b"A90P1 END") != len(end_matches):
        raise FinalizeError(f"{label} transcript has malformed END framing")
    if len(end_matches) != 0:
        raise FinalizeError(f"{label} transcript contains a complete END frame")
    if len(begin_matches) == 0:
        raise FinalizeError(
            f"{label} transcript lacks the fixed-op BEGIN exchange boundary"
        )
    if len(begin_matches) != 1 or not isinstance(begin, Mapping):
        raise FinalizeError(f"{label} transcript BEGIN count/binding is not exact")
    try:
        fields = begin_matches[0].group("fields").decode("ascii")
    except UnicodeDecodeError as exc:
        raise FinalizeError(f"{label} BEGIN fields are not ASCII") from exc
    parsed: dict[str, str] = {}
    for token in fields.split():
        if "=" not in token:
            raise FinalizeError(f"{label} BEGIN field token is malformed")
        key, item = token.split("=", 1)
        if not key or not item or key in parsed:
            raise FinalizeError(f"{label} BEGIN field set is malformed")
        parsed[key] = item
    # A retained no-value BEGIN is only valid for the canonical five-field
    # ``run`` dispatch record.  Do not let a shortened/foreign protocol
    # summary create a new negative evidence namespace.
    if set(parsed) != {"cmd", "seq", "argc", "flags"}:
        raise FinalizeError(f"{label} BEGIN field set is not exact")
    sequence = parsed.get("seq")
    if (
        parsed.get("cmd") != argv[0]
        or not isinstance(sequence, str)
        or re.fullmatch(r"[0-9]+", sequence) is None
        or (len(sequence) > 1 and sequence.startswith("0"))
        or parsed.get("argc") != "5"
        or parsed.get("flags") != inline_protocol_flags_for_argv(argv)
    ):
        raise FinalizeError(f"{label} BEGIN command/sequence/argc/flags is not exact")
    if dict(begin) != parsed:
        raise FinalizeError(f"{label} begin metadata differs from transcript")


def _validate_partial_payload_relation(
    payload: bytes | None, transcript: bytes | None, label: str
) -> None:
    """Match native ``_partial_from_transcript`` payload derivation exactly."""

    if transcript is None:
        if payload is not None:
            raise FinalizeError(f"{label} payload is present without a transcript")
        return
    begins = list(BEGIN_RE.finditer(transcript))
    if not begins:
        if payload is not None:
            raise FinalizeError(f"{label} payload is present without a BEGIN")
        return
    if len(begins) != 1 or payload is None:
        raise FinalizeError(f"{label} payload/BEGIN relation is incomplete")
    expected = transcript[begins[0].end() :]
    if payload != expected:
        raise FinalizeError(f"{label} payload does not equal retained post-BEGIN bytes")


def _validate_transport_no_value(value: object, label: str) -> Mapping[str, object]:
    """Require actual bounded transport evidence for a no-value terminal."""

    if not isinstance(value, Mapping):
        raise FinalizeError(f"{label} transport evidence is missing")
    if set(value) != set(_TRANSPORT_NO_VALUE_EVIDENCE_KEYS):
        raise FinalizeError(f"{label} transport evidence fields are not the exact producer set")
    for key, expected in {
        "transport_no_value": True,
        "bounded": True,
        "payload_bounded": True,
        "transcript_bounded": True,
        "evidence_id": "fixed_op_4",
        "a90r_present": False,
    }.items():
        _require(value, key, expected, label)
    argv = value.get("argv")
    if argv != list(fixed_op_argv()):
        raise FinalizeError(f"{label} transport command is not the fixed op")
    exception_type = value.get("exception_type")
    # A clean negative is authorized only by the native typed transport
    # failure carrying a retained PartialEvidence object.  Legacy timeout,
    # socket, or parser exceptions are ambiguous incidents, even when their
    # text happens to mention a disconnect.
    if exception_type != "TransportFailure":
        raise FinalizeError(f"{label} transport exception type is not exact")
    if value.get("partial_evidence_present") is not True:
        raise FinalizeError(f"{label} typed transport lacks retained partial evidence")
    # ``TransportFailure`` is eligible only when the producer retained the
    # partial exchange itself.  A typed exception with no transcript bytes is
    # indistinguishable from a pre-exchange failure, even if a caller sets the
    # summary boolean by hand.
    if value.get("transcript_base64") is None:
        raise FinalizeError(f"{label} typed transport retained no transcript")
    exception_text = value.get("exception_text")
    if not isinstance(exception_text, str) or not exception_text or len(exception_text) > 512:
        raise FinalizeError(f"{label} transport exception text is not bounded")
    decoded_payload: bytes | None = None
    decoded_transcript: bytes | None = None
    for prefix in ("payload", "transcript"):
        # The producer writes an explicit absence binding when no complete
        # frame arrived.  Missing keys would let a synthetic outcome-only
        # receipt masquerade as a bounded transport failure.
        if any(key not in value for key in (
            f"{prefix}_base64",
            f"{prefix}_sha256",
            f"{prefix}_size",
        )):
            raise FinalizeError(f"{label} {prefix} absence binding is missing")
        encoded = value.get(f"{prefix}_base64")
        digest = value.get(f"{prefix}_sha256")
        size = value.get(f"{prefix}_size")
        if encoded is None:
            if digest is not None or size is not None:
                raise FinalizeError(f"{label} {prefix} absence binding is malformed")
            continue
        if not isinstance(encoded, str) or not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None or type(size) is not int or size < 0 or size > MAX_TRANSPORT_EVIDENCE_BYTES:
            raise FinalizeError(f"{label} {prefix} evidence is not bounded")
        try:
            decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError) as exc:
            raise FinalizeError(f"{label} {prefix} evidence is malformed") from exc
        if (
            len(decoded) != size
            or hashlib.sha256(decoded).hexdigest() != digest
            or b"A90R" in decoded
            or b"A90P1 END" in decoded
        ):
            raise FinalizeError(f"{label} {prefix} evidence is not a no-value frame")
        if prefix == "transcript":
            decoded_transcript = decoded
        else:
            decoded_payload = decoded
    # A retained complete END mapping is authoritative even if a caller
    # redacts the transcript bytes.  The no-value branch is allowed to carry
    # an incomplete BEGIN/payload, never an END/returned frame.
    if value.get("end") is not None:
        raise FinalizeError(f"{label} transport evidence contains a complete END frame")
    _validate_partial_begin_binding(value, decoded_transcript, list(argv), label)
    _validate_partial_payload_relation(decoded_payload, decoded_transcript, label)
    if not inline_is_transport_no_value_payload(decoded_payload):
        raise FinalizeError(
            f"{label} post-BEGIN bytes are not an exact run dispatch prefix"
        )
    for key in ("payload_size", "transcript_size"):
        size = value.get(key)
        if isinstance(size, int) and size > MAX_TRANSPORT_EVIDENCE_BYTES:
            raise FinalizeError(f"{label} transport evidence is oversized")
    return value


def _validate_boot_id_binding(
    public: Mapping[str, object],
    raw: Mapping[str, object],
    journal: Mapping[str, object],
    label: str,
) -> str:
    boot_id = raw.get("boot_id_before_read")
    if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
        raise FinalizeError(f"{label} private pre-read boot_id is malformed")
    digest = hashlib.sha256(boot_id.encode("ascii")).hexdigest()
    for owner in (public, raw, journal):
        if owner.get("boot_id_before_read_sha256") != digest:
            raise FinalizeError(f"{label} pre-read boot_id hash binding differs")
    if journal.get("boot_id_before_read") != boot_id:
        raise FinalizeError(f"{label} journal pre-read boot_id differs")
    return boot_id


def _semantic_claim_key(
    mode: str, candidate_sha256: str, candidate_size: int, boot_id: str
) -> str:
    key = (
        f"verification-024-inline-op\0{mode}\0{candidate_sha256}\0"
        f"{candidate_size}\0{boot_id}"
    ).encode("ascii")
    return hashlib.sha256(key).hexdigest()


def _validate_semantic_claim(
    public: Mapping[str, object],
    raw: Mapping[str, object],
    journal: Mapping[str, object],
    *,
    root: Path,
    mode: str,
    candidate_sha256: str,
    label: str,
) -> Mapping[str, object]:
    """Validate the immutable one-shot claim for this op session."""

    boot_id = raw.get("boot_id_before_read")
    if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
        raise FinalizeError(f"{label} semantic claim boot_id is malformed")
    key_sha256 = _semantic_claim_key(mode, candidate_sha256, BOOT_PREFIX_SIZE, boot_id)
    filename = f"verification-024-inline-op-{key_sha256}.claim.json"
    claim_path = root / PRIVATE_ROOT_NAME / filename
    claim_hash = raw.get("semantic_claim_sha256")
    claim_size = raw.get("semantic_claim_size")
    if raw.get("semantic_claim_path") != str(claim_path) or not isinstance(claim_hash, str) or SHA256_RE.fullmatch(claim_hash) is None or type(claim_size) is not int or claim_size <= 0 or claim_size > MAX_RECEIPT_BYTES:
        raise FinalizeError(f"{label} semantic claim binding is malformed")
    for owner in (raw, journal):
        if owner.get("semantic_claim_path") != str(claim_path) or owner.get("semantic_claim_sha256") != claim_hash or owner.get("semantic_claim_size") != claim_size or owner.get("semantic_claim_key_sha256") != key_sha256 or owner.get("semantic_claimed") is not True:
            raise FinalizeError(f"{label} semantic claim is not cross-bound")
    public_claim = public.get("semantic_claim")
    if not isinstance(public_claim, Mapping) or public_claim.get("filename") != filename or public_claim.get("sha256") != claim_hash or public_claim.get("size") != claim_size or public_claim.get("key_sha256") != key_sha256:
        raise FinalizeError(f"{label} public semantic claim is not exact")
    claim, claim_data, _ = _json(claim_path, root=root / PRIVATE_ROOT_NAME, label=f"{label} semantic claim")
    if hashlib.sha256(claim_data).hexdigest() != claim_hash or len(claim_data) != claim_size:
        raise FinalizeError(f"{label} semantic claim hash/size differs")
    for key, expected in {
        "schema": SEMANTIC_CLAIM_SCHEMA,
        "mode": mode,
        "candidate_sha256": candidate_sha256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "boot_id": boot_id,
        "boot_id_sha256": hashlib.sha256(boot_id.encode("ascii")).hexdigest(),
        "key_sha256": key_sha256,
        "claimed_by_experiment_id": raw.get("experiment_id"),
        "effect_replayed": False,
    }.items():
        _require(claim, key, expected, f"{label} semantic claim")
    return claim


def _manifest_path(path: Path, root: Path, label: str) -> Path:
    if not path.is_absolute():
        path = root / path
    return _path_under(path, root / MANIFEST_ROOT_NAME, label)


def _private_path(path: Path, root: Path, label: str) -> Path:
    if not path.is_absolute():
        path = root / path
    return _path_under(path, root / PRIVATE_ROOT_NAME, label)


def _private_for_experiment(root: Path, experiment_id: str, suffix: str, label: str) -> Path:
    return _private_path(root / PRIVATE_ROOT_NAME / f"{experiment_id}{suffix}", root, label)


def _control_raw_journal(manifest: Mapping[str, object], root: Path) -> tuple[dict[str, object], bytes, dict[str, object], bytes, Path, Path]:
    experiment_id = _experiment_id(manifest, "control manifest")
    private = manifest.get("private_record")
    if not isinstance(private, Mapping):
        raise FinalizeError("control manifest lacks private_record")
    raw_name = f"{experiment_id}.json"
    journal_name = f"{experiment_id}.journal.json"
    if private.get("filename") != raw_name or private.get("journal_filename") != journal_name:
        raise FinalizeError("control private filenames are not derived fixed names")
    raw_path = _private_for_experiment(root, experiment_id, ".json", "control raw")
    journal_path = _private_for_experiment(root, experiment_id, ".journal.json", "control journal")
    raw, raw_bytes, _ = _json(raw_path, root=root / PRIVATE_ROOT_NAME, label="control raw")
    journal, journal_bytes, _ = _json(journal_path, root=root / PRIVATE_ROOT_NAME, label="control journal")
    return raw, raw_bytes, journal, journal_bytes, raw_path, journal_path


def _validate_r3_incident_summary(
    summary: object,
    label: str = "control r3 incident",
) -> dict[str, object]:
    """Require the fixed, consumed-R3 summary shape and identity.

    The checkpoint module owns the file/hash/schema proof.  This additional
    projection check keeps a test seam or future validator revision from
    turning a generic zero-effect summary into the R3 reconciliation record
    retained by the consumed R4 checkpoint and carried into the active R5
    control owner.
    """

    if type(summary) is not dict:
        raise FinalizeError(f"{label} validator returned a non-object")
    for key, expected in {
        "schema": CONTROL_R3_INCIDENT_VALIDATION_SCHEMA,
        "status": "VALIDATED_CONSUMED_ZERO_OP_RESTORED_STATE",
        "experiment_id": CONTROL_R3_EXPERIMENT_ID,
        "next_registered_id": CONTROL_R4_EXPERIMENT_ID,
        "classification": "CLASS_C_UNCHANGED",
        "security_boundary_result": "UNKNOWN_NOT_REACHED",
        "consumed_checkpoint": True,
    }.items():
        _require(summary, key, expected, label)
    incident_facts = summary.get("incident_facts")
    expected_incident_facts = {
        "fixed_op_dispatch_count": 0,
        "effect_dispatched": False,
        "effect_ambiguous": False,
        "effect_replayed": False,
        "partition_writes": False,
        "memory_or_mmio_writes": False,
        "controller_writes": False,
        "protected_memory_read": False,
        "smc": False,
        "panic_before": 1,
        "panic_set_0_applied": True,
        "panic_after_recovery": 1,
        "panic_restore_verified": True,
        "semantic_claim_retained": True,
    }
    if type(incident_facts) is not dict or set(incident_facts) != set(expected_incident_facts):
        raise FinalizeError(f"{label} incident-facts keys are not exact")
    for key, expected in expected_incident_facts.items():
        _require(incident_facts, key, expected, f"{label} incident-facts")

    reconciliation = summary.get("reconciliation")
    expected_reconciliation = {
        "temporary_sysctl_write": True,
        "temporary_sysctl_write_rolled_back": True,
        "writefile_payload_sha256": r2_incident.R3_WRITEFILE_PAYLOAD_SHA256,
        "writefile_payload_size": r2_incident.R3_WRITEFILE_PAYLOAD_SIZE,
    }
    if type(reconciliation) is not dict or set(reconciliation) != set(expected_reconciliation):
        raise FinalizeError(f"{label} reconciliation keys are not exact")
    for key, expected in expected_reconciliation.items():
        _require(reconciliation, key, expected, f"{label} reconciliation")

    checkpoint = summary.get("checkpoint")
    if type(checkpoint) is not dict or set(checkpoint) != {"sha256", "size_bytes"}:
        raise FinalizeError(f"{label} checkpoint descriptor is not exact")
    _require(checkpoint, "sha256", CONTROL_R3_INCIDENT_MANIFEST_SHA256, label)
    _require(checkpoint, "size_bytes", CONTROL_R3_INCIDENT_MANIFEST_SIZE, label)
    return summary


def _validate_r4_incident_summary(
    summary: object,
    label: str = "control r4 incident",
) -> dict[str, object]:
    """Require the fixed consumed-R4 returned-result incident summary."""

    if type(summary) is not dict:
        raise FinalizeError(f"{label} validator returned a non-object")
    for key, expected in {
        "schema": CONTROL_R4_INCIDENT_VALIDATION_SCHEMA,
        "status": "VALIDATED_CONSUMED_RETURNED_FRAMING_INCIDENT",
        "experiment_id": CONTROL_R4_EXPERIMENT_ID,
        "next_registered_id": CONTROL_EXPERIMENT_ID,
        "classification": "CLASS_C_UNCHANGED",
        "security_boundary_result": "UNKNOWN_NOT_REACHED",
        "consumed_checkpoint": True,
    }.items():
        _require(summary, key, expected, label)

    incident_facts = summary.get("incident_facts")
    expected_incident_facts = {
        "fixed_op_dispatch_count": 1,
        "fixed_op_returned": True,
        "effect_dispatched": True,
        "effect_ambiguous": False,
        "effect_replayed": False,
        "partition_writes": False,
        "memory_or_mmio_writes": False,
        "controller_writes": False,
        "protected_memory_read": False,
        "smc": False,
        "panic_before": 1,
        "panic_after_recovery": 1,
        "panic_restore_verified": True,
        "semantic_claim_retained": True,
    }
    if type(incident_facts) is not dict or set(incident_facts) != set(expected_incident_facts):
        raise FinalizeError(f"{label} incident-facts keys are not exact")
    for key, expected in expected_incident_facts.items():
        _require(incident_facts, key, expected, f"{label} incident-facts")

    exact_sections: tuple[tuple[str, Mapping[str, object]], ...] = (
        ("source", r2_incident.R4_SOURCE_PINS),
        ("target", r2_incident.R4_TARGET_PINS),
        (
            "post_incident_readonly_health",
            r2_incident.R4_POST_INCIDENT_READONLY_HEALTH_PINS,
        ),
        ("panic_transition", r2_incident.R4_PANIC_TRANSITION_PINS),
        ("fixed_op", r2_incident.R4_FIXED_OP_PINS),
        ("parser_incident", r2_incident.R4_PARSER_INCIDENT_PINS),
    )
    for key, expected in exact_sections:
        actual = summary.get(key)
        if type(actual) is not dict or actual != dict(expected):
            raise FinalizeError(f"{label} {key} projection is not exact")
    fixed_op = summary["fixed_op"]
    assert isinstance(fixed_op, dict)
    if fixed_op.get("result_grade") != "RETURNED_SENTINEL_CANDIDATE_NOT_CONTROL_PASS":
        raise FinalizeError(f"{label} result grade is not exact NOT_CONTROL_PASS")

    expected_artifacts = {
        role: dict(descriptor)
        for role, descriptor in r2_incident.R4_ARTIFACT_PINS.items()
    }
    artifacts = summary.get("artifact_descriptors")
    if type(artifacts) is not dict or artifacts != expected_artifacts:
        raise FinalizeError(f"{label} artifact descriptors are not exact")

    checkpoint = summary.get("checkpoint")
    expected_checkpoint = {
        "sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
        "size_bytes": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
    }
    if type(checkpoint) is not dict or set(checkpoint) != set(expected_checkpoint):
        raise FinalizeError(f"{label} checkpoint descriptor is not exact")
    for key, expected in expected_checkpoint.items():
        _require(checkpoint, key, expected, label)
    return summary


def _validate_control_predecessors(
    journal: Mapping[str, object],
    label: str = "control journal",
    *,
    root: Path | None = None,
) -> tuple[str, int, dict[str, object], dict[str, object], dict[str, object]]:
    """Validate historical, consumed-R2/R3/R4, and active-R5 bindings.

    R2, R3, and R4 are consumed checkpoints, never executable fallbacks.  The
    R5 producer durably records the exact preclaim, keeps the legacy R2 capsule
    section and R3/R4 reconciliation sections, and adds the R5 reconciliation
    containing the canonical R4 incident summary.  Rebuilding every source
    here closes semantic, path, and serialization substitution gaps.
    """

    section = journal.get("control_r2_predecessor")
    if not isinstance(section, dict):
        raise FinalizeError(f"{label} r2 predecessor section is missing")
    if set(section) != {
        "preclaim_sha256",
        "preclaim_size",
        "capsule",
        "capsule_sha256",
        "capsule_size",
    }:
        raise FinalizeError(f"{label} r2 predecessor fields are not exact")

    try:
        capsule = control_retry.build_predecessor_capsule()
    except BaseException as exc:
        raise FinalizeError("control r2 predecessor capsule cannot be rebuilt") from exc
    if type(capsule) is not dict or set(capsule) != {
        "schema",
        "semantic_capsule",
        "historical_git_verification",
    }:
        raise FinalizeError("control r2 predecessor capsule schema is not exact")
    if capsule.get("schema") != CONTROL_R2_PREDECESSOR_CAPSULE_SCHEMA:
        raise FinalizeError("control r2 predecessor capsule schema differs")
    try:
        capsule_bytes = control_retry.canonical_capsule_bytes(capsule)
    except BaseException as exc:
        raise FinalizeError("control r2 predecessor capsule is not canonical") from exc
    if type(capsule_bytes) is not bytes:
        raise FinalizeError("control r2 predecessor capsule bytes are not exact")
    capsule_sha256 = hashlib.sha256(capsule_bytes).hexdigest()
    capsule_size = len(capsule_bytes)
    if capsule_sha256 != CONTROL_R2_PREDECESSOR_CAPSULE_SHA256:
        raise FinalizeError("control r2 predecessor capsule hash is not fixed")
    if capsule_size != CONTROL_R2_PREDECESSOR_CAPSULE_SIZE:
        raise FinalizeError("control r2 predecessor capsule size is not fixed")
    retained_capsule = section.get("capsule")
    if type(retained_capsule) is not dict:
        raise FinalizeError("control r2 predecessor capsule differs from producer")
    try:
        retained_capsule_bytes = control_retry.canonical_capsule_bytes(retained_capsule)
    except BaseException as exc:
        raise FinalizeError("control r2 predecessor retained capsule is not canonical") from exc
    if retained_capsule_bytes != capsule_bytes:
        raise FinalizeError("control r2 predecessor capsule bytes differ from producer")
    if (
        hashlib.sha256(retained_capsule_bytes).hexdigest()
        != CONTROL_R2_PREDECESSOR_CAPSULE_SHA256
        or len(retained_capsule_bytes) != CONTROL_R2_PREDECESSOR_CAPSULE_SIZE
    ):
        raise FinalizeError("control r2 predecessor retained capsule descriptor is not fixed")
    _require(section, "capsule_sha256", capsule_sha256, label)
    _require(section, "capsule_size", capsule_size, label)

    try:
        preclaim = inline_probe._control_r5_preclaim()
        preclaim_bytes = inline_probe.json_bytes(preclaim)
    except BaseException as exc:
        raise FinalizeError("control r5 predecessor preclaim cannot be rebuilt") from exc
    if type(preclaim) is not dict or type(preclaim_bytes) is not bytes:
        raise FinalizeError("control r5 predecessor preclaim is not exact")
    if set(preclaim) != {
        "schema",
        "status",
        "experiment_id",
        "predecessor_experiment_id",
        "consumed_r2_experiment_id",
        "consumed_r3_experiment_id",
        "consumed_r4_experiment_id",
        "mode",
        "replay_safe",
        "predecessor_capsule",
        "r2_incident",
        "r3_incident",
        "r4_incident",
    } | set(CONTROL_SAFETY_EFFECT_FIELDS):
        raise FinalizeError("control r5 preclaim fields are not exact")
    if preclaim.get("schema") != CONTROL_R5_PRECLAIM_SCHEMA:
        raise FinalizeError("control r5 preclaim schema differs")
    if preclaim.get("status") != CONTROL_R5_PRECLAIM_STATUS:
        raise FinalizeError("control r5 preclaim status differs")
    if preclaim.get("experiment_id") != CONTROL_EXPERIMENT_ID:
        raise FinalizeError("control r5 preclaim active ID differs")
    if preclaim.get("predecessor_experiment_id") != CONTROL_PREDECESSOR_EXPERIMENT_ID:
        raise FinalizeError("control r5 preclaim historical ID differs")
    if preclaim.get("consumed_r2_experiment_id") != CONTROL_R2_EXPERIMENT_ID:
        raise FinalizeError("control r5 preclaim consumed R2 ID differs")
    if preclaim.get("consumed_r3_experiment_id") != CONTROL_R3_EXPERIMENT_ID:
        raise FinalizeError("control r5 preclaim consumed R3 ID differs")
    if preclaim.get("consumed_r4_experiment_id") != CONTROL_R4_EXPERIMENT_ID:
        raise FinalizeError("control r5 preclaim consumed R4 ID differs")
    if preclaim.get("mode") != "control" or preclaim.get("replay_safe") is not False:
        raise FinalizeError("control r5 preclaim replay policy differs")
    for field in CONTROL_SAFETY_EFFECT_FIELDS:
        _require(preclaim, field, False, "control r5 preclaim")
    expected_predecessor = {
        "schema": CONTROL_R2_PREDECESSOR_CAPSULE_SCHEMA,
        "sha256": CONTROL_R2_PREDECESSOR_CAPSULE_SHA256,
        "size": CONTROL_R2_PREDECESSOR_CAPSULE_SIZE,
        "historical_pins_policy": CONTROL_R5_HISTORICAL_PINS_POLICY,
    }
    predecessor_descriptor = preclaim.get("predecessor_capsule")
    if type(predecessor_descriptor) is not dict or set(predecessor_descriptor) != set(expected_predecessor):
        raise FinalizeError("control r5 preclaim capsule fields are not exact")
    if predecessor_descriptor != expected_predecessor:
        raise FinalizeError("control r5 preclaim capsule descriptor differs")
    expected_r2_descriptor = {
        "schema": CONTROL_R2_INCIDENT_VALIDATION_SCHEMA,
        "sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
    }
    r2_descriptor = preclaim.get("r2_incident")
    if type(r2_descriptor) is not dict or set(r2_descriptor) != set(expected_r2_descriptor):
        raise FinalizeError("control r5 preclaim R2 incident fields are not exact")
    if r2_descriptor != expected_r2_descriptor:
        raise FinalizeError("control r5 preclaim R2 incident descriptor differs")
    expected_r3_descriptor = {
        "schema": CONTROL_R3_INCIDENT_VALIDATION_SCHEMA,
        "sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
    }
    r3_descriptor = preclaim.get("r3_incident")
    if type(r3_descriptor) is not dict or set(r3_descriptor) != set(expected_r3_descriptor):
        raise FinalizeError("control r5 preclaim R3 incident fields are not exact")
    if r3_descriptor != expected_r3_descriptor:
        raise FinalizeError("control r5 preclaim R3 incident descriptor differs")
    expected_r4_descriptor = {
        "schema": CONTROL_R4_INCIDENT_VALIDATION_SCHEMA,
        "sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
        "size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
    }
    r4_descriptor = preclaim.get("r4_incident")
    if type(r4_descriptor) is not dict or set(r4_descriptor) != set(expected_r4_descriptor):
        raise FinalizeError("control r5 preclaim R4 incident fields are not exact")
    if r4_descriptor != expected_r4_descriptor:
        raise FinalizeError("control r5 preclaim R4 incident descriptor differs")
    preclaim_sha256 = hashlib.sha256(preclaim_bytes).hexdigest()
    _require(section, "preclaim_sha256", preclaim_sha256, label)
    _require(section, "preclaim_size", len(preclaim_bytes), label)

    incident_root = REPO_ROOT if root is None else root
    r2_reconciliation = journal.get("control_r3_reconciliation")
    if not isinstance(r2_reconciliation, dict):
        raise FinalizeError(f"{label} r3 reconciliation section is missing")
    if set(r2_reconciliation) != {"preclaim_sha256", "preclaim_size", "r2_incident"}:
        raise FinalizeError(f"{label} r3 reconciliation fields are not exact")
    _require(r2_reconciliation, "preclaim_sha256", preclaim_sha256, label)
    _require(r2_reconciliation, "preclaim_size", len(preclaim_bytes), label)
    try:
        r2_incident_summary = r2_incident.validate_r2_incident(incident_root)
    except BaseException as exc:
        raise FinalizeError("control r2 incident checkpoint cannot be validated") from exc
    if type(r2_incident_summary) is not dict:
        raise FinalizeError("control r2 incident validator returned a non-object")
    retained_r2_summary = r2_reconciliation.get("r2_incident")
    if type(retained_r2_summary) is not dict:
        raise FinalizeError("control r3 reconciliation R2 summary is missing")
    try:
        expected_r2_bytes = inline_probe.json_bytes(r2_incident_summary)
        retained_r2_bytes = inline_probe.json_bytes(retained_r2_summary)
    except BaseException as exc:
        raise FinalizeError("control r3 reconciliation summary is not canonical") from exc
    if retained_r2_bytes != expected_r2_bytes:
        raise FinalizeError("control r3 reconciliation R2 summary differs")

    r3_reconciliation = journal.get("control_r4_reconciliation")
    if not isinstance(r3_reconciliation, dict):
        raise FinalizeError(f"{label} r4 reconciliation section is missing")
    if set(r3_reconciliation) != {"preclaim_sha256", "preclaim_size", "r3_incident"}:
        raise FinalizeError(f"{label} r4 reconciliation fields are not exact")
    _require(r3_reconciliation, "preclaim_sha256", preclaim_sha256, label)
    _require(r3_reconciliation, "preclaim_size", len(preclaim_bytes), label)
    try:
        r3_incident_summary = r2_incident.validate_r3_incident(incident_root)
    except BaseException as exc:
        raise FinalizeError("control r3 incident checkpoint cannot be validated") from exc
    r3_incident_summary = _validate_r3_incident_summary(r3_incident_summary)
    retained_r3_summary = r3_reconciliation.get("r3_incident")
    if type(retained_r3_summary) is not dict:
        raise FinalizeError("control r4 reconciliation R3 summary is missing")
    try:
        expected_r3_bytes = inline_probe.json_bytes(r3_incident_summary)
        retained_r3_bytes = inline_probe.json_bytes(retained_r3_summary)
    except BaseException as exc:
        raise FinalizeError("control r4 reconciliation summary is not canonical") from exc
    if retained_r3_bytes != expected_r3_bytes:
        raise FinalizeError("control r4 reconciliation R3 summary differs")

    r4_reconciliation = journal.get("control_r5_reconciliation")
    if not isinstance(r4_reconciliation, dict):
        raise FinalizeError(f"{label} r5 reconciliation section is missing")
    if set(r4_reconciliation) != {"preclaim_sha256", "preclaim_size", "r4_incident"}:
        raise FinalizeError(f"{label} r5 reconciliation fields are not exact")
    _require(r4_reconciliation, "preclaim_sha256", preclaim_sha256, label)
    _require(r4_reconciliation, "preclaim_size", len(preclaim_bytes), label)
    try:
        r4_incident_summary = r2_incident.validate_r4_incident(incident_root)
    except BaseException as exc:
        raise FinalizeError("control r4 incident checkpoint cannot be validated") from exc
    r4_incident_summary = _validate_r4_incident_summary(r4_incident_summary)
    retained_r4_summary = r4_reconciliation.get("r4_incident")
    if type(retained_r4_summary) is not dict:
        raise FinalizeError("control r5 reconciliation R4 summary is missing")
    try:
        expected_r4_bytes = inline_probe.json_bytes(r4_incident_summary)
        retained_r4_bytes = inline_probe.json_bytes(retained_r4_summary)
    except BaseException as exc:
        raise FinalizeError("control r5 reconciliation summary is not canonical") from exc
    if retained_r4_bytes != expected_r4_bytes:
        raise FinalizeError("control r5 reconciliation R4 summary differs")
    return (
        capsule_sha256,
        capsule_size,
        r2_incident_summary,
        r3_incident_summary,
        r4_incident_summary,
    )


def _validate_control_r2_predecessor(
    journal: Mapping[str, object],
    label: str = "control journal",
    *,
    root: Path | None = None,
) -> tuple[str, int, dict[str, object]]:
    """Compatibility wrapper retaining the historical helper name."""

    capsule_sha256, capsule_size, r2_summary, _r3_summary, _r4_summary = _validate_control_predecessors(
        journal, label, root=root
    )
    return capsule_sha256, capsule_size, r2_summary


def _validate_flash_reference(
    value: object,
    *,
    profile: str,
    expected_predecessor: str,
    root: Path,
    label: str,
) -> Mapping[str, object]:
    """Re-open the exact flash source named by a private receipt.

    The inline probe stores a path/hash/size tuple in its private receipt.
    Re-validating that file here closes the gap where a later replacement of
    the referenced flash journal could leave a superficially valid tuple.
    """

    if not isinstance(value, Mapping):
        raise FinalizeError(f"{label} flash journal binding is missing")
    for key in ("path", "sha256", "size"):
        if key not in value:
            raise FinalizeError(f"{label} flash journal {key!r} binding is missing")
    source_path_value = value.get("path")
    source_hash = value.get("sha256")
    source_size = value.get("size")
    if (
        not isinstance(source_path_value, str)
        or not isinstance(source_hash, str)
        or SHA256_RE.fullmatch(source_hash) is None
        or type(source_size) is not int
        or source_size <= 0
        or source_size > MAX_RECEIPT_BYTES
    ):
        raise FinalizeError(f"{label} flash journal hash/size binding is malformed")
    expected_source_path = (
        root / PRIVATE_ROOT_NAME / FLASH_JOURNAL_NAMES[profile]
    ).resolve(strict=False)
    try:
        supplied_source_path = Path(source_path_value)
        if not supplied_source_path.is_absolute():
            supplied_source_path = root / supplied_source_path
        _reject_symlink_components(supplied_source_path, f"{label} flash journal")
        supplied_source_path = supplied_source_path.resolve(strict=False)
    except (TypeError, ValueError, OSError) as exc:
        raise FinalizeError(f"{label} flash journal path is not fixed") from exc
    if supplied_source_path != expected_source_path or source_path_value != str(expected_source_path):
        raise FinalizeError(f"{label} flash journal path is not the fixed {profile} producer journal")
    try:
        source = verify_flash_journal(
            supplied_source_path, profile, root=root
        )
    except BaseException as exc:
        raise FinalizeError(f"{label} flash source journal is not complete") from exc
    if (
        source.get("sha256") != source_hash
        or source.get("size") != source_size
        or source.get("profile") != profile
        or source.get("predecessor_sha256") != expected_predecessor
    ):
        raise FinalizeError(f"{label} flash source journal hash/provenance differs")
    return value


def validate_control(path: Path, root: Path) -> dict[str, object]:
    manifest, data, checked = _json(_manifest_path(path, root, "control manifest"), root=root / MANIFEST_ROOT_NAME, label="control manifest")
    if checked != (root / MANIFEST_ROOT_NAME / CONTROL_MANIFEST_NAME).resolve(strict=False):
        raise FinalizeError("control manifest path is not the fixed V024 control producer")
    if manifest.get("schema") != "sdm855-a90-inline-remapper-mid-public-v1":
        raise FinalizeError("control manifest schema is not exact")
    _require(manifest, "experiment_id", CONTROL_EXPERIMENT_ID, "control manifest")
    _require(manifest, "mode", "control", "control manifest")
    _require_hash(manifest.get("candidate_sha256"), CONTROL_SHA256, "control candidate")
    _require_size(manifest.get("candidate_size"), BOOT_PREFIX_SIZE, "control candidate")
    for key, value in {
        "target_verified": True,
        "target_evaluation": "VERIFIED",
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": TARGET_RUNTIME,
        "outcome": "CONTROL_PASS",
        "dispatch_count": 1,
        "dispatch_returned": True,
        "dispatch_failed": False,
        "effect_dispatched": True,
        "effect_ambiguous": False,
        "effect_replayed": False,
        "health_after_ok": True,
        "cleanup_ok": True,
        "panic_on_oops_before": 1,
        "panic_on_oops_zero_set": True,
        "panic_on_oops_zero_verified": True,
        "panic_on_oops_restored": True,
        "automatic_retries": False,
        **CONTROL_SAFETY_EFFECT_PROJECTION,
        "flash_journal_bound": True,
        "flash_profile": "control",
        "flash_image_sha256": CONTROL_SHA256,
        "flash_readback_sha256": CONTROL_SHA256,
        "flash_predecessor_sha256": ROLLBACK_SHA256,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
        "r4_incident_manifest_sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
        "r4_incident_manifest_size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
        "r4_returned_result_restored_validated": True,
    }.items():
        _require(manifest, key, value, "control manifest")
    manifest_attestation = _validate_current_boot_attestation(
        manifest.get("current_boot_attestation"),
        CONTROL_SHA256,
        "control manifest",
        require_paths=False,
    )
    expected_panic_transition = {
        "before": 1,
        "zero_write_attempted": True,
        "zero_set": True,
        "zero_verified": True,
        "restore_write_attempted": True,
        "restored": True,
        "restore_deferred": False,
        "proof_frame_ids": [
            "panic_before",
            "panic_set_0",
            "panic_zero_verify",
            "panic_set_1",
            "panic_restore_verify",
        ],
    }
    if manifest.get("panic_transition") != expected_panic_transition:
        raise FinalizeError("control manifest panic transition proof is not exact")
    fixed = manifest.get("fixed_op")
    if not isinstance(fixed, Mapping):
        raise FinalizeError("control fixed_op is missing")
    if set(fixed) != {
        "op",
        "args",
        "buffer_size",
        "buffer_sha256",
        "rc",
        "status",
        "value",
    }:
        raise FinalizeError("control public fixed_op fields are not exact")
    for key, value in {
        "op": 4,
        "args": [],
        "buffer_size": 0x58,
        "buffer_sha256": _fixed_op_buffer_hash(),
        "rc": 0,
        "status": "ok",
        "value": "0x000000000000c071",
    }.items():
        # The buffer hash is checked by the probe itself; keep a strict shape
        # here while accepting an independently produced exact pinned hash.
        if key == "buffer_sha256":
            if fixed.get(key) != _fixed_op_buffer_hash():
                raise FinalizeError("control fixed_op buffer hash is malformed")
        else:
            _require(fixed, key, value, "control fixed_op")
    raw, raw_bytes, journal, journal_bytes, raw_path, journal_path = _control_raw_journal(manifest, root)
    raw_hash = manifest.get("raw_snapshot_sha256")
    raw_size = manifest.get("raw_snapshot_size")
    journal_hash = manifest.get("journal_sha256")
    journal_size = manifest.get("journal_size")
    if raw_hash != hashlib.sha256(raw_bytes).hexdigest() or raw_size != len(raw_bytes):
        raise FinalizeError("control raw hash/size does not match manifest")
    if journal_hash != hashlib.sha256(journal_bytes).hexdigest() or journal_size != len(journal_bytes):
        raise FinalizeError("control journal hash/size does not match manifest")
    if type(raw_size) is not int or type(journal_size) is not int:
        raise FinalizeError("control private hash/size binding is malformed")
    safety_effect = _validate_control_safety_effect_projection(
        manifest, raw, journal
    )
    (
        predecessor_capsule_sha256,
        predecessor_capsule_size,
        r2_incident_summary,
        r3_incident_summary,
        r4_incident_summary,
    ) = _validate_control_predecessors(journal, root=root)
    _require(raw, "schema", "sdm855-a90-inline-remapper-mid-private-v1", "control raw")
    _require(raw, "experiment_id", CONTROL_EXPERIMENT_ID, "control raw")
    _require(raw, "mode", "control", "control raw")
    _require(journal, "experiment_id", CONTROL_EXPERIMENT_ID, "control journal")
    _require(journal, "mode", "control", "control journal")
    for owner, owner_label in (
        (raw, "control raw"),
        (journal, "control journal"),
    ):
        _require(owner, "experiment_id", CONTROL_EXPERIMENT_ID, owner_label)
        _require(owner, "automatic_retries", False, owner_label)
        _require(
            owner,
            "r2_incident_manifest_sha256",
            CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            owner_label,
        )
        _require(
            owner,
            "r2_incident_manifest_size",
            CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            owner_label,
        )
        _require(owner, "r2_zero_effect_validated", True, owner_label)
        _require(
            owner,
            "r3_incident_manifest_sha256",
            CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            owner_label,
        )
        _require(
            owner,
            "r3_incident_manifest_size",
            CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            owner_label,
        )
        _require(owner, "r3_zero_op_restored_validated", True, owner_label)
        _require(
            owner,
            "r4_incident_manifest_sha256",
            CONTROL_R4_INCIDENT_MANIFEST_SHA256,
            owner_label,
        )
        _require(
            owner,
            "r4_incident_manifest_size",
            CONTROL_R4_INCIDENT_MANIFEST_SIZE,
            owner_label,
        )
        _require(owner, "r4_returned_result_restored_validated", True, owner_label)
    _require_hash(raw.get("candidate_sha256"), CONTROL_SHA256, "control raw candidate")
    _require_size(raw.get("candidate_size"), BOOT_PREFIX_SIZE, "control raw candidate")
    raw_flash = raw.get("flash_journal")
    if not isinstance(raw_flash, Mapping) or raw_flash.get("profile") != "control" or raw_flash.get("image_sha256") != CONTROL_SHA256 or raw_flash.get("readback_sha256") != CONTROL_SHA256 or raw_flash.get("predecessor_sha256") != ROLLBACK_SHA256:
        raise FinalizeError("control raw flash provenance is not exact")
    for key in ("path", "sha256", "size"):
        if key not in raw_flash:
            raise FinalizeError(f"control raw flash journal {key!r} binding is missing")
    _require_hash(raw_flash.get("sha256"), raw_flash.get("sha256"), "control raw flash journal")
    if type(raw_flash.get("size")) is not int or raw_flash.get("size") <= 0:
        raise FinalizeError("control raw flash journal size is malformed")
    if manifest.get("flash_journal_sha256") != raw_flash.get("sha256") or manifest.get("flash_journal_size") != raw_flash.get("size"):
        raise FinalizeError("control public/raw flash journal hash binding differs")
    _validate_flash_reference(
        raw_flash,
        profile="control",
        expected_predecessor=ROLLBACK_SHA256,
        root=root,
        label="control raw",
    )
    _require(raw, "outcome", "CONTROL_PASS", "control raw")
    _require(raw, "dispatch_count", 1, "control raw")
    _require(raw, "effect_dispatched", True, "control raw")
    _require(raw, "effect_ambiguous", False, "control raw")
    _require(raw, "effect_replayed", False, "control raw")
    target = raw.get("target")
    _require_inline_target(target, "control raw target")
    raw_attestation = _validate_current_boot_attestation(
        raw.get("current_boot_attestation"), CONTROL_SHA256, "control raw"
    )
    journal_attestation = _validate_current_boot_attestation(
        journal.get("current_boot_attestation"), CONTROL_SHA256, "control journal"
    )
    _require_hash(journal.get("candidate_sha256"), CONTROL_SHA256, "control journal candidate")
    _require_size(journal.get("candidate_size"), BOOT_PREFIX_SIZE, "control journal candidate")
    _require(journal, "op", 4, "control journal")
    _require(journal, "op_args", [], "control journal")
    _require_inline_target(journal.get("target"), "control journal target")
    if not isinstance(journal.get("flash_journal"), Mapping) or dict(journal["flash_journal"]) != dict(raw_flash):
        raise FinalizeError("control journal flash receipt binding differs")
    journal_health = journal.get("health_after")
    if not isinstance(journal_health, Mapping) or journal_health.get("ok") is not True:
        raise FinalizeError("control journal health is missing")
    _require_inline_target(journal_health.get("target"), "control journal final target")
    _require_selftest(journal_health.get("selftest"), "control journal final")
    for key in (
        "captured_sha256",
        "captured_size",
        "expected_sha256",
        "expected_size",
        "cleanup_ok",
        "sysfs_uevent",
        "stat",
    ):
        if manifest_attestation.get(key) != raw_attestation.get(key) or raw_attestation.get(key) != journal_attestation.get(key):
            raise FinalizeError(f"control current boot attestation {key!r} is not cross-bound")
    control_boot_id = _validate_boot_id_binding(manifest, raw, journal, "control")
    _validate_semantic_claim(
        manifest,
        raw,
        journal,
        root=root,
        mode="control",
        candidate_sha256=CONTROL_SHA256,
        label="control",
    )
    fixed_measurement = _validate_fixed_measurement(
        raw.get("fixed_op_measurement"),
        "0x000000000000c071",
        "control raw",
    )
    _validate_fixed_measurement(
        journal.get("fixed_op_measurement"),
        "0x000000000000c071",
        "control journal",
    )
    if fixed.get("value") != fixed_measurement.get("value"):
        raise FinalizeError("control public/private fixed-op values differ")
    raw_fixed_frame = _validate_fixed_op_frame(
        raw.get("frames"),
        "0x000000000000c071",
        "control raw",
    )
    journal_fixed_frame = _validate_fixed_op_frame(
        journal.get("frames"),
        "0x000000000000c071",
        "control journal",
    )
    if dict(raw_fixed_frame) != dict(journal_fixed_frame):
        raise FinalizeError("control raw/journal fixed-op frames differ")
    _validate_frame_list(
        raw.get("frames"), "control raw", restored=True, allow_fixed=True,
        include_health=True,
    )
    _validate_frame_list(
        journal.get("frames"), "control journal", restored=True, allow_fixed=True,
        include_health=True,
    )
    _require_panic_frames_equal(raw.get("frames"), journal.get("frames"), "control")
    raw_health = raw.get("health_after")
    if not isinstance(raw_health, Mapping) or raw_health.get("ok") is not True:
        raise FinalizeError("control raw final health is missing")
    raw_health_target = raw_health.get("target")
    raw_health_selftest = raw_health.get("selftest")
    if not isinstance(raw_health_target, Mapping) or not isinstance(raw_health_selftest, Mapping):
        raise FinalizeError("control raw final health facts are missing")
    if dict(raw_health_target) != dict(journal_health.get("target")) or dict(raw_health_selftest) != dict(journal_health.get("selftest")):
        raise FinalizeError("control raw/journal final health facts differ")
    _validate_inline_frame_payload_semantics(
        raw.get("frames"),
        target=target,
        attestation=raw_attestation,
        candidate_sha256=CONTROL_SHA256,
        candidate_size=BOOT_PREFIX_SIZE,
        boot_id_before_read=control_boot_id,
        label="control raw",
        include_health=True,
        health_target=raw_health_target,
        health_selftest=raw_health_selftest,
    )
    _validate_inline_frame_payload_semantics(
        journal.get("frames"),
        target=journal.get("target"),  # type: ignore[arg-type]
        attestation=journal_attestation,
        candidate_sha256=CONTROL_SHA256,
        candidate_size=BOOT_PREFIX_SIZE,
        boot_id_before_read=control_boot_id,
        label="control journal",
        include_health=True,
        health_target=journal_health.get("target"),  # type: ignore[arg-type]
        health_selftest=journal_health.get("selftest"),  # type: ignore[arg-type]
    )
    if raw.get("error") != journal.get("error"):
        raise FinalizeError("control raw/journal error bindings differ")
    if raw.get("error") is not None or journal.get("error") is not None:
        raise FinalizeError("control completed receipt carries an error")
    expected_transition = {
        "before": 1,
        "zero_write_attempted": True,
        "zero_set": True,
        "zero_verified": True,
        "restore_write_attempted": True,
        "restored": True,
        "restore_deferred": False,
        "proof_frame_ids": [
            "panic_before",
            "panic_set_0",
            "panic_zero_verify",
            "panic_set_1",
            "panic_restore_verify",
        ],
    }
    if raw.get("panic_transition") != expected_transition or journal.get("panic_transition") != expected_transition or manifest.get("panic_transition") != expected_transition:
        raise FinalizeError("control panic transition is not exact across receipts")
    for owner, label in ((raw, "control raw"), (journal, "control journal")):
        for key, expected in {
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
            "panic_on_oops_restored": True,
            "panic_restore_deferred": False,
            "effect_dispatched": True,
            "dispatch_returned": True,
            "dispatch_failed": False,
        }.items():
            _require(owner, key, expected, label)
    health_after = raw.get("health_after")
    if not isinstance(health_after, Mapping) or health_after.get("ok") is not True or raw.get("cleanup_ok") is not True or raw.get("panic_on_oops_restored") is not True:
        raise FinalizeError("control raw health/cleanup/panic is incomplete")
    _require_inline_target(health_after.get("target"), "control raw final target")
    _require_selftest(health_after.get("selftest"), "control raw final")
    if journal.get("schema") != "sdm855-a90-inline-remapper-mid-journal-v1" or journal.get("experiment_id") != manifest.get("experiment_id") or journal.get("mode") != "control" or journal.get("status") != "CONTROL_VERIFIED":
        raise FinalizeError("control journal is not CONTROL_VERIFIED")
    for key, value in {
        "outcome": "CONTROL_PASS",
        "dispatch_count": 1,
        "effect_dispatched": True,
        "effect_ambiguous": False,
        "effect_replayed": False,
        "cleanup_ok": True,
        "panic_on_oops_restored": True,
    }.items():
        _require(journal, key, value, "control journal")
    _require(journal, "value", "0x000000000000c071", "control journal")
    _require(raw, "value", "0x000000000000c071", "control raw")
    started_value = manifest.get("started_utc")
    started = _utc(started_value, "control manifest started")
    for owner, owner_label in (
        (raw, "control raw"),
        (journal, "control journal"),
    ):
        owner_started_value = owner.get("started_utc")
        owner_started = _utc(owner_started_value, f"{owner_label} started")
        if owner_started_value != started_value or owner_started != started:
            raise FinalizeError("control start times are not hash-bound")
    completed_value = manifest.get("completed_utc")
    completed = _utc(completed_value, "control manifest")
    if started > completed:
        raise FinalizeError("control started after completion")
    for owner, owner_label in (
        (raw, "control raw"),
        (journal, "control journal"),
    ):
        owner_completed_value = owner.get("completed_utc")
        owner_completed = _utc(owner_completed_value, owner_label)
        if owner_completed_value != completed_value or owner_completed != completed:
            raise FinalizeError("control completion times are not hash-bound")
    return {
        "kind": "control",
        "experiment_id": _experiment_id(manifest, "control manifest"),
        "path": str(checked),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "manifest_sha256": hashlib.sha256(data).hexdigest(),
        "manifest_size": len(data),
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "raw_size": len(raw_bytes),
        "journal_sha256": hashlib.sha256(journal_bytes).hexdigest(),
        "journal_size": len(journal_bytes),
        "completed_utc": manifest["completed_utc"],
        "value": "0x000000000000c071",
        **safety_effect,
        "candidate_sha256": CONTROL_SHA256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "target_dmid": TARGET_DMID,
        "current_boot_attestation": dict(manifest_attestation),
        "boot_id_before_read_sha256": manifest.get("boot_id_before_read_sha256"),
        "fixed_op_measurement": dict(fixed_measurement),
        "semantic_claim_sha256": raw.get("semantic_claim_sha256"),
        "semantic_claim_size": raw.get("semantic_claim_size"),
        "semantic_claim_key_sha256": raw.get("semantic_claim_key_sha256"),
        "predecessor_capsule_sha256": predecessor_capsule_sha256,
        "predecessor_capsule_size": predecessor_capsule_size,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
        "r4_incident_manifest_sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
        "r4_incident_manifest_size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
        "r4_returned_result_restored_validated": True,
        "raw_path": str(raw_path),
        "journal_path": str(journal_path),
    }


def _load_public_or_private(path: Path, root: Path, label: str) -> tuple[dict[str, object], bytes, Path]:
    if not path.is_absolute():
        path = root / path
    checked = _path_under(path, root, label)
    return _json(checked, root=root, label=label)


def _load_evidence_json(path: Path, repo_root: Path, label: str) -> tuple[dict[str, object], bytes, Path]:
    """Accept only a manifest-root or private-root receipt path."""

    if not path.is_absolute():
        path = repo_root / path
    manifest_root = repo_root / MANIFEST_ROOT_NAME
    private_root = repo_root / PRIVATE_ROOT_NAME
    try:
        checked = _path_under(path, manifest_root, label)
        return _json(checked, root=manifest_root, label=label)
    except FinalizeError as manifest_error:
        try:
            checked = _path_under(path, private_root, label)
            return _json(checked, root=private_root, label=label)
        except FinalizeError:
            raise manifest_error


def validate_read(path: Path, root: Path, control: Mapping[str, object]) -> dict[str, object]:
    manifest, data, checked = _load_public_or_private(_manifest_path(path, root, "read manifest"), root / MANIFEST_ROOT_NAME, "read manifest")
    if checked != (root / MANIFEST_ROOT_NAME / READ_SOURCE_MANIFEST_NAME).resolve(strict=False):
        raise FinalizeError("read manifest path is not the fixed V024 read producer")
    if manifest.get("schema") != "sdm855-a90-inline-remapper-mid-public-v1":
        raise FinalizeError("read manifest schema is not exact")
    # The read authorization edge is not allowed to trust a caller-supplied
    # control summary.  Re-validate the fixed control manifest/private
    # journal here and require the exact result object used for the binding;
    # this keeps a direct validator caller from cross-splicing a forged
    # control mapping into an otherwise plausible read receipt.
    if not isinstance(control, Mapping):
        raise FinalizeError("read control receipt is missing")
    validated_control = validate_control(
        root / MANIFEST_ROOT_NAME / CONTROL_MANIFEST_NAME,
        root,
    )
    if dict(control) != dict(validated_control):
        raise FinalizeError("read control receipt is not the complete fixed control result")
    control = validated_control
    _require(manifest, "experiment_id", READ_SOURCE_EXPERIMENT_ID, "read manifest")
    _require(manifest, "mode", "read", "read manifest")
    _require_hash(manifest.get("candidate_sha256"), READ_SHA256, "read candidate")
    _require_size(manifest.get("candidate_size"), BOOT_PREFIX_SIZE, "read candidate")
    for key, value in {
        "target_verified": True,
        "target_evaluation": "VERIFIED",
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": TARGET_RUNTIME,
        "effect_replayed": False,
        "automatic_retries": False,
        "partition_writes": False,
        "flash_journal_bound": True,
        "flash_profile": "read",
        "flash_image_sha256": READ_SHA256,
        "flash_readback_sha256": READ_SHA256,
        "flash_predecessor_sha256": CONTROL_SHA256,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
        "r4_incident_manifest_sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
        "r4_incident_manifest_size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
        "r4_returned_result_restored_validated": True,
    }.items():
        _require(manifest, key, value, "read manifest")
    read_attestation = _validate_current_boot_attestation(
        manifest.get("current_boot_attestation"),
        READ_SHA256,
        "read manifest",
        require_paths=False,
    )
    _require(manifest, "panic_on_oops_before", 1, "read manifest")
    _require(manifest, "panic_on_oops_zero_set", True, "read manifest")
    _require(manifest, "panic_on_oops_zero_verified", True, "read manifest")
    if not isinstance(manifest.get("boot_id_before_read_sha256"), str) or not SHA256_RE.fullmatch(manifest["boot_id_before_read_sha256"]):
        raise FinalizeError("read manifest pre-read boot_id hash is missing")
    completed = _utc(manifest.get("completed_utc"), "read manifest")
    binding = manifest.get("control_manifest")
    if not isinstance(binding, Mapping):
        raise FinalizeError("read manifest lacks control receipt binding")
    for key, expected in {
        "experiment_id": CONTROL_EXPERIMENT_ID,
        "mode": "control",
        "candidate_sha256": CONTROL_SHA256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "value": "0x000000000000c071",
        "target_dmid": TARGET_DMID,
        "predecessor_capsule_sha256": CONTROL_R2_PREDECESSOR_CAPSULE_SHA256,
        "predecessor_capsule_size": CONTROL_R2_PREDECESSOR_CAPSULE_SIZE,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
        "r4_incident_manifest_sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
        "r4_incident_manifest_size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
        "r4_returned_result_restored_validated": True,
    }.items():
        _require(binding, key, expected, "read control binding")
    for key, expected in {
        "predecessor_capsule_sha256": CONTROL_R2_PREDECESSOR_CAPSULE_SHA256,
        "predecessor_capsule_size": CONTROL_R2_PREDECESSOR_CAPSULE_SIZE,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
        "r4_incident_manifest_sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
        "r4_incident_manifest_size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
        "r4_returned_result_restored_validated": True,
    }.items():
        _require(control, key, expected, "validated control receipt")
    _validate_current_boot_attestation(
        binding.get("current_boot_attestation"),
        CONTROL_SHA256,
        "read control binding attestation",
        require_paths=False,
    )
    _validate_fixed_measurement(
        binding.get("fixed_op_measurement"),
        "0x000000000000c071",
        "read control binding fixed-op",
    )
    for key in ("candidate_sha256", "candidate_size", "value", "completed_utc", "manifest_sha256", "manifest_size", "raw_sha256", "raw_size", "journal_sha256", "journal_size", "current_boot_attestation", "boot_id_before_read_sha256", "fixed_op_measurement", "r2_incident_manifest_sha256", "r2_incident_manifest_size", "r2_zero_effect_validated", "r3_incident_manifest_sha256", "r3_incident_manifest_size", "r3_zero_op_restored_validated", "r4_incident_manifest_sha256", "r4_incident_manifest_size", "r4_returned_result_restored_validated"):
        if binding.get(key) != control.get(key) and not (key == "candidate_sha256" and binding.get(key) == CONTROL_SHA256):
            raise FinalizeError(f"read control binding field {key!r} differs")
    value_present = manifest.get("returned_value_present") is True
    experiment_id = _experiment_id(manifest, "read manifest")
    private_record = manifest.get("private_record")
    if not isinstance(private_record, Mapping) or private_record.get("filename") != f"{experiment_id}.json" or private_record.get("journal_filename") != f"{experiment_id}.journal.json":
        raise FinalizeError("read manifest lacks fixed private raw/journal derivation")
    raw_path = _private_path(root / PRIVATE_ROOT_NAME / f"{experiment_id}.json", root, "read raw")
    journal_path = _private_path(root / PRIVATE_ROOT_NAME / f"{experiment_id}.journal.json", root, "read journal")
    raw, raw_bytes, _ = _json(raw_path, root=root / PRIVATE_ROOT_NAME, label="read raw")
    journal, journal_bytes, _ = _json(journal_path, root=root / PRIVATE_ROOT_NAME, label="read journal")
    if raw.get("error") != journal.get("error"):
        raise FinalizeError("read raw/journal error bindings differ")
    if manifest.get("returned_value_present") is True and (
        raw.get("error") is not None or journal.get("error") is not None
    ):
        raise FinalizeError("read returned receipt carries an error")
    raw_hash = manifest.get("raw_snapshot_sha256")
    raw_size = manifest.get("raw_snapshot_size")
    journal_hash = manifest.get("journal_sha256")
    journal_size = manifest.get("journal_size")
    if raw_hash != hashlib.sha256(raw_bytes).hexdigest() or raw_size != len(raw_bytes):
        raise FinalizeError("read raw hash/size does not match manifest")
    if journal_hash != hashlib.sha256(journal_bytes).hexdigest() or journal_size != len(journal_bytes):
        raise FinalizeError("read journal hash/size does not match manifest")
    if type(raw_size) is not int or type(journal_size) is not int:
        raise FinalizeError("read private hash/size binding is malformed")
    if raw.get("schema") != "sdm855-a90-inline-remapper-mid-private-v1" or raw.get("mode") != "read":
        raise FinalizeError("read raw schema/mode is not exact")
    raw_flash = raw.get("flash_journal")
    if not isinstance(raw_flash, Mapping) or raw_flash.get("profile") != "read" or raw_flash.get("image_sha256") != READ_SHA256 or raw_flash.get("readback_sha256") != READ_SHA256 or raw_flash.get("predecessor_sha256") != CONTROL_SHA256:
        raise FinalizeError("read raw flash provenance is not exact")
    _validate_flash_reference(
        raw_flash,
        profile="read",
        expected_predecessor=CONTROL_SHA256,
        root=root,
        label="read raw",
    )
    # The read image must have been flashed after the complete control
    # receipt.  Equality (or an older flash receipt) leaves the read source
    # unauthorised even when its candidate/hash fields look correct.
    try:
        read_flash_source = verify_flash_journal(
            Path(str(raw_flash.get("path"))), "read", root=root
        )
        read_flash_completed = _utc(
            read_flash_source.get("record", {}).get("completed_utc")
            if isinstance(read_flash_source.get("record"), Mapping)
            else None,
            "read flash journal",
        )
        control_completed = _utc(control.get("completed_utc"), "control receipt")
    except BaseException as exc:
        raise FinalizeError("read flash completion cannot be validated") from exc
    if read_flash_completed <= control_completed:
        raise FinalizeError(
            "read flash receipt must complete strictly after control receipt"
        )
    if read_flash_completed >= completed:
        raise FinalizeError(
            "read flash receipt must complete before the read probe receipt"
        )
    if manifest.get("flash_journal_sha256") != raw_flash.get("sha256") or manifest.get("flash_journal_size") != raw_flash.get("size"):
        raise FinalizeError("read public/raw flash journal hash binding differs")
    raw_control = raw.get("control_manifest")
    if not isinstance(raw_control, Mapping):
        raise FinalizeError("read raw control receipt binding is missing")
    if any(raw_control.get(key) != binding.get(key) for key in binding):
        raise FinalizeError("read public/private control receipt bindings differ")
    journal_flash = journal.get("flash_journal")
    if not isinstance(journal_flash, Mapping) or dict(journal_flash) != dict(raw_flash):
        raise FinalizeError("read journal flash receipt binding differs")
    journal_control = journal.get("control_manifest")
    if not isinstance(journal_control, Mapping) or any(journal_control.get(key) != binding.get(key) for key in binding):
        raise FinalizeError("read journal control receipt binding differs")
    for owner, label in (
        (raw_control, "read raw control binding"),
        (journal_control, "read journal control binding"),
    ):
        for key, expected in {
            "predecessor_capsule_sha256": CONTROL_R2_PREDECESSOR_CAPSULE_SHA256,
            "predecessor_capsule_size": CONTROL_R2_PREDECESSOR_CAPSULE_SIZE,
            "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
            "r4_incident_manifest_sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
            "r4_incident_manifest_size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
            "r4_returned_result_restored_validated": True,
        }.items():
            _require(owner, key, expected, label)
    for owner, label in ((raw, "read raw"), (journal, "read journal")):
        for key, expected in {
            "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
            "r4_incident_manifest_sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
            "r4_incident_manifest_size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
            "r4_returned_result_restored_validated": True,
        }.items():
            _require(owner, key, expected, label)
    for key in ("experiment_id", "manifest_sha256", "manifest_size", "raw_sha256", "raw_size", "journal_sha256", "journal_size", "completed_utc", "candidate_sha256", "candidate_size", "value", "predecessor_capsule_sha256", "predecessor_capsule_size", "r2_incident_manifest_sha256", "r2_incident_manifest_size", "r2_zero_effect_validated", "r3_incident_manifest_sha256", "r3_incident_manifest_size", "r3_zero_op_restored_validated", "r4_incident_manifest_sha256", "r4_incident_manifest_size", "r4_returned_result_restored_validated"):
        if type(raw_control.get(key)) is not type(control.get(key)) or raw_control.get(key) != control.get(key):
            raise FinalizeError(f"read raw control binding field {key!r} differs")
    _require_hash(raw.get("candidate_sha256"), READ_SHA256, "read raw candidate")
    _require_size(raw.get("candidate_size"), BOOT_PREFIX_SIZE, "read raw candidate")
    raw_target = raw.get("target")
    _require_inline_target(raw_target, "read raw target")
    raw_attestation = _validate_current_boot_attestation(
        raw.get("current_boot_attestation"), READ_SHA256, "read raw"
    )
    journal_attestation = _validate_current_boot_attestation(
        journal.get("current_boot_attestation"), READ_SHA256, "read journal"
    )
    for key in (
        "captured_sha256",
        "captured_size",
        "expected_sha256",
        "expected_size",
        "cleanup_ok",
        "sysfs_uevent",
        "stat",
    ):
        if read_attestation.get(key) != raw_attestation.get(key) or raw_attestation.get(key) != journal_attestation.get(key):
            raise FinalizeError(f"read current boot attestation {key!r} is not cross-bound")
    read_boot_id = _validate_boot_id_binding(manifest, raw, journal, "read")
    _validate_semantic_claim(
        manifest,
        raw,
        journal,
        root=root,
        mode="read",
        candidate_sha256=READ_SHA256,
        label="read",
    )
    if type(manifest.get("returned_value_present")) is not bool:
        raise FinalizeError("read public returned_value_present is not boolean")
    if type(raw.get("effect_replayed")) is not bool or raw.get("effect_replayed") is not False:
        raise FinalizeError("read raw replay field is not exact")
    if type(journal.get("effect_replayed")) is not bool or journal.get("effect_replayed") is not False:
        raise FinalizeError("read journal replay field is not exact")
    if journal.get("schema") != "sdm855-a90-inline-remapper-mid-journal-v1" or journal.get("experiment_id") != experiment_id or journal.get("mode") != "read":
        raise FinalizeError("read journal schema/mode is not exact")
    _require_hash(journal.get("candidate_sha256"), READ_SHA256, "read journal candidate")
    _require_size(journal.get("candidate_size"), BOOT_PREFIX_SIZE, "read journal candidate")
    _require(journal, "op", 4, "read journal")
    _require(journal, "op_args", [], "read journal")
    _require_inline_target(journal.get("target"), "read journal target")
    for owner, label in ((raw, "read raw"), (journal, "read journal")):
        for key, expected in {
            "panic_on_oops_before": 1,
            "panic_on_oops_zero_set": True,
            "panic_on_oops_zero_verified": True,
        }.items():
            _require(owner, key, expected, label)
    fixed_public = manifest.get("fixed_op")
    if not isinstance(fixed_public, Mapping):
        raise FinalizeError("read manifest fixed_op is missing")
    if set(fixed_public) != {
        "op",
        "args",
        "buffer_size",
        "buffer_sha256",
        "rc",
        "status",
        "value",
    }:
        raise FinalizeError("read public fixed_op fields are not exact")
    for key, expected in {
        "op": 4,
        "args": [],
        "buffer_size": 0x58,
        "buffer_sha256": _fixed_op_buffer_hash(),
    }.items():
        _require(fixed_public, key, expected, "read manifest fixed_op")
    fixed_journal = journal.get("fixed_op")
    if not isinstance(fixed_journal, Mapping):
        raise FinalizeError("read journal fixed_op is missing")
    for key, expected in {
        "op": 4,
        "args": [],
        "buffer_size": 0x58,
        "buffer_sha256": _fixed_op_buffer_hash(),
    }.items():
        _require(fixed_journal, key, expected, "read journal fixed_op")
    if type(journal.get("dispatch_count")) is not int or journal.get("dispatch_count") != 1 or type(journal.get("effect_dispatched")) is not bool or journal.get("effect_dispatched") is not True:
        raise FinalizeError("read journal dispatch fields are not exact")
    for key in ("effect_dispatched", "dispatch_returned", "dispatch_failed"):
        if key not in manifest or key not in raw or key not in journal:
            raise FinalizeError(f"read {key} dispatch projection is missing")
        if not (manifest.get(key) == raw.get(key) == journal.get(key)):
            raise FinalizeError(f"read {key} dispatch projection differs")
    raw_value = raw.get("value")
    raw_measurement = raw.get("fixed_op_measurement")
    journal_value = journal.get("value")
    if raw_value is not None:
        if not isinstance(raw_value, str) or re.fullmatch(r"0x[0-9a-f]{16}", raw_value) is None:
            raise FinalizeError("read raw returned value is malformed")
        _validate_fixed_measurement(raw_measurement, raw_value, "read raw")
        _validate_fixed_measurement(
            journal.get("fixed_op_measurement"), raw_value, "read journal"
        )
        for key, expected in {
            "rc": 0,
            "status": "ok",
            "value": raw_value,
        }.items():
            _require(fixed_public, key, expected, "read manifest fixed_op")
        if journal_value != raw_value:
            raise FinalizeError("read journal returned value differs from raw")
    elif raw_measurement is not None or journal_value is not None:
        raise FinalizeError("read no-value terminal contains a forged value field")
    value_present = bool(manifest.get("returned_value_present"))
    if value_present != (raw_value is not None):
        raise FinalizeError("read public/raw returned-value presence differs")
    if value_present:
        value_digest = hashlib.sha256(str(raw_value).encode("ascii")).hexdigest()
        if manifest.get("returned_value_sha256") != value_digest:
            raise FinalizeError("read public returned-value digest differs")
        expected_outcome = "MAP_FAILED" if raw_value == "0xffffffffffffffff" else (
            "READABLE_SECURITY_INDICATOR"
            if int(raw_value, 16) <= 0xFFFFFFFF
            else "INCIDENT"
        )
        if expected_outcome == "INCIDENT":
            raise FinalizeError("read returned value is outside the exact 32-bit result domain")
        if expected_outcome == "MAP_FAILED":
            raise FinalizeError("read map-failure marker is not a readable security indicator")
        _require(manifest, "outcome", expected_outcome, "read manifest")
        _require(raw, "outcome", expected_outcome, "read raw")
        _require(journal, "outcome", expected_outcome, "read journal")
        # The probe rewrites the durable terminal status during publication;
        # retain that final serialized status instead of accepting the earlier
        # transient EFFECT_RETURNED marker.
        _require(journal, "status", "READABLE_SECURITY_INDICATOR", "read journal")
        _require(manifest, "dispatch_count", 1, "read manifest")
        _require(manifest, "effect_dispatched", True, "read manifest")
        _require(manifest, "effect_ambiguous", False, "read manifest")
        _require(raw, "dispatch_count", 1, "read raw")
        _require(raw, "effect_dispatched", True, "read raw")
        _require(raw, "effect_ambiguous", False, "read raw")
        _require(journal, "effect_ambiguous", False, "read journal")
        _require(manifest, "dispatch_returned", True, "read manifest")
        _require(manifest, "dispatch_failed", False, "read manifest")
        _require(manifest, "cleanup_ok", True, "read manifest")
        _require(raw, "dispatch_returned", True, "read raw")
        _require(raw, "dispatch_failed", False, "read raw")
        _require(raw, "cleanup_ok", True, "read raw")
        _require(journal, "dispatch_returned", True, "read journal")
        _require(journal, "dispatch_failed", False, "read journal")
        _require(journal, "cleanup_ok", True, "read journal")
        if (
            raw.get("panic_on_oops_restored") is not True
            or manifest.get("panic_on_oops_restored") is not True
            or raw.get("panic_restore_deferred") is not False
            or manifest.get("panic_restore_deferred") is not False
        ):
            raise FinalizeError("read returned terminal lacks panic restore")
        if raw.get("completed_utc") is not None and _utc(raw.get("completed_utc"), "read raw") != completed:
            raise FinalizeError("read raw completion differs from manifest")
        _require(journal, "panic_on_oops_restored", True, "read journal")
        _require(journal, "panic_restore_deferred", False, "read journal")
        expected_transition = {
            "before": 1,
            "zero_write_attempted": True,
            "zero_set": True,
            "zero_verified": True,
            "restore_write_attempted": True,
            "restored": True,
            "restore_deferred": False,
            "proof_frame_ids": [
                "panic_before",
                "panic_set_0",
                "panic_zero_verify",
                "panic_set_1",
                "panic_restore_verify",
            ],
        }
        if raw.get("panic_transition") != expected_transition or journal.get("panic_transition") != expected_transition or manifest.get("panic_transition") != expected_transition:
            raise FinalizeError("read returned panic transition is not exact")
        _validate_frame_list(
            raw.get("frames"), "read raw", restored=True, allow_fixed=True,
            include_health=False,
        )
        _validate_frame_list(
            journal.get("frames"), "read journal", restored=True, allow_fixed=True,
            include_health=False,
        )
        _require_panic_frames_equal(raw.get("frames"), journal.get("frames"), "read returned")
        _validate_inline_frame_payload_semantics(
            raw.get("frames"),
            target=raw_target,  # type: ignore[arg-type]
            attestation=raw_attestation,
            candidate_sha256=READ_SHA256,
            candidate_size=BOOT_PREFIX_SIZE,
            boot_id_before_read=read_boot_id,
            label="read raw",
            include_health=False,
        )
        _validate_inline_frame_payload_semantics(
            journal.get("frames"),
            target=journal.get("target"),  # type: ignore[arg-type]
            attestation=journal_attestation,
            candidate_sha256=READ_SHA256,
            candidate_size=BOOT_PREFIX_SIZE,
            boot_id_before_read=read_boot_id,
            label="read journal",
            include_health=False,
        )
        raw_fixed_frame = _validate_fixed_op_frame(
            raw.get("frames"), raw_value, "read raw"
        )
        journal_fixed_frame = _validate_fixed_op_frame(
            journal.get("frames"), raw_value, "read journal"
        )
        if dict(raw_fixed_frame) != dict(journal_fixed_frame):
            raise FinalizeError("read raw/journal fixed-op frames differ")
        if journal.get("completed_utc") is None or _utc(journal.get("completed_utc"), "read journal") != completed:
            raise FinalizeError("read journal completion differs from manifest")
        return {
            "kind": "read",
            "experiment_id": experiment_id,
            "path": str(checked),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "raw_size": len(raw_bytes),
            "journal_sha256": hashlib.sha256(journal_bytes).hexdigest(),
            "journal_size": len(journal_bytes),
            "value_present": True,
            "value": raw_value,
            "completed_utc": manifest.get("completed_utc"),
            "semantic_claim_sha256": raw.get("semantic_claim_sha256"),
            "semantic_claim_size": raw.get("semantic_claim_size"),
            "semantic_claim_key_sha256": raw.get("semantic_claim_key_sha256"),
            "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
            "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
            "r2_zero_effect_validated": True,
            "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
            "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
            "r3_zero_op_restored_validated": True,
        }
    _require(manifest, "dispatch_count", 1, "read manifest")
    _require(manifest, "effect_dispatched", True, "read manifest")
    _require(manifest, "outcome", "REFUSED_AT_MID_CANDIDATE", "read manifest")
    _require(manifest, "effect_ambiguous", True, "read manifest")
    _require(manifest, "dispatch_returned", False, "read manifest")
    _require(manifest, "dispatch_failed", True, "read manifest")
    _require(manifest, "returned_value_sha256", None, "read manifest")
    _require(manifest, "panic_on_oops_restored", False, "read manifest")
    _require(manifest, "panic_restore_deferred", True, "read manifest")
    _require(manifest, "cleanup_ok", False, "read manifest")
    _require(manifest, "health_after_ok", False, "read manifest")
    _require(manifest, "transport_no_value", True, "read manifest")
    _require(raw, "outcome", "REFUSED_AT_MID_CANDIDATE", "read raw")
    _require(raw, "effect_ambiguous", True, "read raw")
    _require(raw, "dispatch_count", 1, "read raw")
    _require(raw, "effect_dispatched", True, "read raw")
    _require(raw, "dispatch_returned", False, "read raw")
    _require(raw, "dispatch_failed", True, "read raw")
    _require(raw, "panic_on_oops_restored", False, "read raw")
    _require(raw, "panic_restore_deferred", True, "read raw")
    _require(raw, "cleanup_ok", False, "read raw")
    _require(raw, "fixed_op_measurement", None, "read raw")
    if raw.get("completed_utc") is not None and _utc(raw.get("completed_utc"), "read raw") != completed:
        raise FinalizeError("read raw completion differs from manifest")
    if journal.get("mode") != "read" or journal.get("outcome") != "REFUSED_AT_MID_CANDIDATE" or journal.get("status") != "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED":
        raise FinalizeError("read journal is not the exact refusal receipt")
    if journal.get("effect_ambiguous") is not True or journal.get("dispatch_count") != 1:
        raise FinalizeError("read journal refusal is not ambiguous one-shot evidence")
    _require(journal, "effect_dispatched", True, "read journal")
    _require(journal, "dispatch_returned", False, "read journal")
    _require(journal, "dispatch_failed", True, "read journal")
    _require(journal, "panic_on_oops_restored", False, "read journal")
    _require(journal, "panic_restore_deferred", True, "read journal")
    _require(journal, "cleanup_ok", False, "read journal")
    _require(journal, "fixed_op_measurement", None, "read journal")
    for key, expected in {
        "rc": None,
        "status": None,
        "value": None,
    }.items():
        _require(fixed_public, key, expected, "read manifest fixed_op")
    expected_transition = {
        "before": 1,
        "zero_write_attempted": True,
        "zero_set": True,
        "zero_verified": True,
        "restore_write_attempted": False,
        "restored": False,
        "restore_deferred": True,
        "proof_frame_ids": [
            "panic_before",
            "panic_set_0",
            "panic_zero_verify",
        ],
    }
    if raw.get("panic_transition") != expected_transition or journal.get("panic_transition") != expected_transition or manifest.get("panic_transition") != expected_transition:
        raise FinalizeError("read refusal panic transition is not exact")
    _validate_frame_list(
        raw.get("frames"), "read raw", restored=False, allow_fixed=False,
        include_health=False,
    )
    _validate_frame_list(
        journal.get("frames"), "read journal", restored=False, allow_fixed=False,
        include_health=False,
    )
    _require_panic_frames_equal(raw.get("frames"), journal.get("frames"), "read refusal")
    _validate_inline_frame_payload_semantics(
        raw.get("frames"),
        target=raw_target,  # type: ignore[arg-type]
        attestation=raw_attestation,
        candidate_sha256=READ_SHA256,
        candidate_size=BOOT_PREFIX_SIZE,
        boot_id_before_read=read_boot_id,
        label="read raw",
        include_health=False,
    )
    _validate_inline_frame_payload_semantics(
        journal.get("frames"),
        target=journal.get("target"),  # type: ignore[arg-type]
        attestation=journal_attestation,
        candidate_sha256=READ_SHA256,
        candidate_size=BOOT_PREFIX_SIZE,
        boot_id_before_read=read_boot_id,
        label="read journal",
        include_health=False,
    )
    error = raw.get("error")
    _validate_transport_no_value(error, "read refusal transport")
    if error != journal.get("error"):
        raise FinalizeError("read refusal raw/journal transport errors differ")
    journal_completed = _utc(journal.get("completed_utc"), "read journal")
    if journal_completed != completed:
        raise FinalizeError("read manifest and journal completion times differ")
    return {
        "kind": "read",
        "experiment_id": experiment_id,
        "path": str(checked),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "raw_size": len(raw_bytes),
        "journal_sha256": hashlib.sha256(journal_bytes).hexdigest(),
        "journal_size": len(journal_bytes),
        "value_present": False,
        "completed_utc": manifest.get("completed_utc"),
        "semantic_claim_sha256": raw.get("semantic_claim_sha256"),
        "semantic_claim_size": raw.get("semantic_claim_size"),
        "semantic_claim_key_sha256": raw.get("semantic_claim_key_sha256"),
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
        "r4_incident_manifest_sha256": CONTROL_R4_INCIDENT_MANIFEST_SHA256,
        "r4_incident_manifest_size": CONTROL_R4_INCIDENT_MANIFEST_SIZE,
        "r4_returned_result_restored_validated": True,
    }


def validate_last_kmsg(path: Path, root: Path) -> dict[str, object]:
    checked_manifest = _manifest_path(path, root, "last-kmsg signature")
    value, data, checked = _json(checked_manifest, root=root / MANIFEST_ROOT_NAME, label="last-kmsg signature")
    if checked != (root / MANIFEST_ROOT_NAME / LAST_KMSG_MANIFEST_NAME).resolve(strict=False):
        raise FinalizeError("last-kmsg manifest path is not the fixed V024 producer")
    if value.get("schema") != "sdm855-a90-last-kmsg-capture-public-v2":
        raise FinalizeError("last-kmsg signature schema is not exact")
    for key, expected in {
        "target_verified": True,
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": "0.9.285",
        "transport_module": "tools.a90_pa28_live",
        "transport_source": "tools/a90_pa28_live.py",
        "reboot_dispatched": False,
        "last_kmsg_read_once": True,
        "boot_id_changed": True,
    }.items():
        _require(value, key, expected, "last-kmsg manifest")
    source = value.get("read_source")
    if not isinstance(source, Mapping):
        raise FinalizeError("last-kmsg read source binding is missing")
    source_experiment_id = source.get("experiment_id")
    if source_experiment_id != READ_SOURCE_EXPERIMENT_ID:
        raise FinalizeError("last-kmsg read source experiment ID is not the fixed V024 source")
    source_summary = _validate_fixed_read_source(root, source_experiment_id)
    for key in (
        "experiment_id",
        "manifest_sha256",
        "manifest_size",
        "raw_sha256",
        "raw_size",
        "journal_sha256",
        "journal_size",
        "completed_utc",
        "source_pre_read_boot_id_sha256",
    ):
        if source.get(key) != source_summary.get(key):
            raise FinalizeError(f"last-kmsg read source field {key!r} is not hash-bound")
    current_boot_hash = value.get("current_boot_id_sha256")
    if not isinstance(current_boot_hash, str) or SHA256_RE.fullmatch(current_boot_hash) is None:
        raise FinalizeError("last-kmsg current boot_id hash is missing")
    if value.get("source_pre_read_boot_id_sha256") != source_summary["source_pre_read_boot_id_sha256"]:
        raise FinalizeError("last-kmsg source pre-read boot_id hash differs")
    # This collector is a read-only observation.  Its successful public
    # producer schema deliberately has no effect-dispatch fields; accepting a
    # synthetic effect marker would blur the provenance boundary.
    if "effect_dispatched" in value or "effect_dispatched_count" in value:
        raise FinalizeError("last-kmsg public receipt invents effect provenance")
    signature = value.get("exact_reset_signature")
    if not isinstance(signature, Mapping):
        raise FinalizeError("last-kmsg exact_reset_signature is missing")
    exact = {
        "status": "EXACT_V024_MID_NONSECURE_WDT",
        "debug_level_decimal": 1145654596,
        "upload_cause": "Non Secure Watchdog Bark",
        "tz_reset_reason": "TZBSP_ERR_FATAL_NON_SECURE_WDT",
        "a90r_count": 0,
    }
    for key, expected in exact.items():
        _require(signature, key, expected, "last-kmsg signature")
    _require(signature, "reference_offsets", {
        "bark": 2_033_780,
        "last_pet": 2_033_888,
        "debug_level": 2_038_584,
        "upload_cause": 2_054_304,
        "collect_upload": 2_054_492,
        "tz_reason": 2_054_678,
    }, "last-kmsg signature")
    _require(signature, "reference_offsets_match", True, "last-kmsg signature")
    offsets = signature.get("ordered_offsets")
    offset_keys = ("bark", "last_pet", "debug_level", "upload_cause", "collect_upload", "tz_reason")
    if not isinstance(offsets, dict) or tuple(offsets) != offset_keys:
        raise FinalizeError("last-kmsg offsets do not use the exact ordered keys")
    offset_values = [offsets[key] for key in offset_keys]
    if any(type(item) is not int or item < 0 for item in offset_values) or offset_values != sorted(set(offset_values)):
        raise FinalizeError("last-kmsg offsets are not strictly ordered")
    delta: object = None
    for key in ("bark_last_pet_delta_seconds", "bark_minus_last_pet_seconds", "last_pet_to_bark_seconds"):
        if key in signature:
            delta = signature[key]
            break
    if delta is None:
        raise FinalizeError("last-kmsg bark/last-pet delta is missing")
    try:
        number = float(delta)
    except (TypeError, ValueError) as exc:
        raise FinalizeError("last-kmsg bark/last-pet delta is malformed") from exc
    if not math.isfinite(number) or not 10.0 <= number <= 12.0:
        raise FinalizeError("last-kmsg bark/last-pet delta is outside the bounded range")
    private = value.get("private_record")
    if not isinstance(private, Mapping):
        raise FinalizeError("last-kmsg private record binding is missing")
    experiment_id = _experiment_id(value, "last-kmsg")
    if experiment_id != LAST_KMSG_EXPERIMENT_ID:
        raise FinalizeError("last-kmsg experiment ID is not the fixed V024 producer")
    raw_name = private.get("filename")
    metadata_name = private.get("metadata_filename") or private.get("record_filename")
    journal_name = private.get("journal_filename")
    if raw_name != f"{experiment_id}.last_kmsg.bin" or metadata_name != f"{experiment_id}.private.json" or journal_name != f"{experiment_id}.journal.json":
        raise FinalizeError("last-kmsg private filenames are not fixed")
    captured_name = private.get("captured_log_filename")
    if captured_name != f"{experiment_id}.last_kmsg.raw.bin":
        raise FinalizeError("last-kmsg captured binary filename is not fixed")
    raw_path = _private_path(root / PRIVATE_ROOT_NAME / str(raw_name), root, "last-kmsg signature")
    captured_path = _private_path(root / PRIVATE_ROOT_NAME / str(captured_name), root, "last-kmsg raw")
    metadata_path = _private_path(root / PRIVATE_ROOT_NAME / str(metadata_name), root, "last-kmsg metadata")
    journal_path = _private_path(root / PRIVATE_ROOT_NAME / str(journal_name), root, "last-kmsg journal")
    signature_bytes = _stable_bytes(raw_path, root=root / PRIVATE_ROOT_NAME, label="last-kmsg signature", max_bytes=MAX_RECEIPT_BYTES)
    if value.get("retained_sha256") != hashlib.sha256(signature_bytes).hexdigest() or value.get("retained_size") != len(signature_bytes):
        raise FinalizeError("last-kmsg published signature hash/size does not match")
    metadata, metadata_bytes, _ = _json(metadata_path, root=root / PRIVATE_ROOT_NAME, label="last-kmsg metadata")
    if metadata.get("schema") != "sdm855-a90-last-kmsg-capture-private-v2" or metadata.get("experiment_id") != experiment_id:
        raise FinalizeError("last-kmsg metadata schema/experiment is not exact")
    metadata_target = metadata.get("target")
    if not isinstance(metadata_target, Mapping):
        raise FinalizeError("last-kmsg metadata target is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": "0.9.285",
    }.items():
        _require(metadata_target, key, expected, "last-kmsg metadata target")
    metadata_records = metadata.get("records")
    record_payloads = _validate_last_transport_records(
        metadata_records, "last-kmsg metadata transport"
    )
    last_version_identity = _parse_v024_version_payload(
        record_payloads[0], "last-kmsg version"
    )
    if metadata_target.get("runtime") != last_version_identity["runtime_version"]:
        raise FinalizeError("last-kmsg metadata runtime differs from decoded version")
    for key in ("runtime_build", "kernel"):
        if key in metadata_target and metadata_target.get(key) != last_version_identity[key]:
            raise FinalizeError(f"last-kmsg metadata {key} differs from decoded version")
    if value.get("runtime") != last_version_identity["runtime_version"]:
        raise FinalizeError("last-kmsg public runtime differs from decoded version")
    decoded_cmdline = _last_cmdline(record_payloads[1])
    if metadata_target.get("cmdline") != decoded_cmdline:
        raise FinalizeError("last-kmsg metadata cmdline differs from decoded payload")
    try:
        decoded_current_boot = record_payloads[2].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise FinalizeError("last-kmsg current boot_id payload is not ASCII") from exc
    if decoded_current_boot.endswith("\r\n"):
        decoded_current_boot = decoded_current_boot[:-2]
    elif decoded_current_boot.endswith("\n"):
        decoded_current_boot = decoded_current_boot[:-1]
    if BOOT_ID_RE.fullmatch(decoded_current_boot) is None:
        raise FinalizeError("last-kmsg current boot_id payload is malformed")
    if metadata.get("current_boot_id") != decoded_current_boot:
        raise FinalizeError("last-kmsg current boot_id differs from source record")
    if metadata.get("selftest_status") != "ok":
        raise FinalizeError("last-kmsg selftest terminal status is not exact")
    if metadata.get("read_source") != dict(source_summary):
        raise FinalizeError("last-kmsg metadata read source binding differs")
    metadata_source_boot = metadata.get("source_pre_read_boot_id")
    metadata_current_boot = metadata.get("current_boot_id")
    if not isinstance(metadata_source_boot, str) or BOOT_ID_RE.fullmatch(metadata_source_boot) is None or not isinstance(metadata_current_boot, str) or BOOT_ID_RE.fullmatch(metadata_current_boot) is None or metadata_source_boot == metadata_current_boot:
        raise FinalizeError("last-kmsg metadata boot-session join is not exact")
    if metadata.get("source_pre_read_boot_id") != source_summary.get("source_pre_read_boot_id"):
        raise FinalizeError("last-kmsg metadata source boot_id differs")
    if metadata.get("current_boot_id_sha256") != current_boot_hash or hashlib.sha256(metadata_current_boot.encode("ascii")).hexdigest() != current_boot_hash:
        raise FinalizeError("last-kmsg metadata current boot_id hash differs")
    if metadata.get("boot_id_changed") is not True:
        raise FinalizeError("last-kmsg metadata boot_id change is not proved")
    metadata_completed = _utc(metadata.get("completed_utc"), "last-kmsg metadata")
    public_completed = _utc(value.get("completed_utc"), "last-kmsg")
    if metadata_completed != public_completed:
        raise FinalizeError("last-kmsg metadata completion differs from public")
    metadata_signature = metadata.get("exact_reset_signature")
    if not isinstance(metadata_signature, Mapping) or dict(metadata_signature) != dict(signature):
        raise FinalizeError("last-kmsg metadata signature differs from public")
    metadata_log = metadata.get("last_kmsg")
    if not isinstance(metadata_log, Mapping) or metadata_log.get("sha256") != hashlib.sha256(signature_bytes).hexdigest() or metadata_log.get("size") != len(signature_bytes):
        raise FinalizeError("last-kmsg metadata signature hash/size does not match")
    captured_metadata = metadata.get("captured_log")
    if not isinstance(captured_metadata, Mapping):
        raise FinalizeError("last-kmsg metadata captured binary is missing")
    captured_bytes = _stable_bytes(captured_path, root=root / PRIVATE_ROOT_NAME, label="last-kmsg raw", max_bytes=MAX_RECEIPT_BYTES)
    if record_payloads[3] != captured_bytes:
        raise FinalizeError("last-kmsg payload record differs from retained binary")
    captured_hash = hashlib.sha256(captured_bytes).hexdigest()
    if captured_metadata.get("filename") != captured_name or captured_metadata.get("sha256") != captured_hash or captured_metadata.get("size") != len(captured_bytes):
        raise FinalizeError("last-kmsg metadata captured binary hash/size does not match")
    if value.get("captured_log_sha256") != captured_hash or value.get("captured_log_size") != len(captured_bytes):
        raise FinalizeError("last-kmsg published captured binary hash/size does not match")
    parsed_signature, _ = _parse_signature_bytes(signature_bytes)
    if parsed_signature != dict(signature):
        raise FinalizeError("last-kmsg derived signature differs from public signature")
    try:
        recomputed = parse_exact_reset_signature(captured_bytes)
    except BaseException as exc:
        raise FinalizeError("last-kmsg raw binary cannot be parsed") from exc
    if not isinstance(recomputed, Mapping) or recomputed.get("status") != "EXACT_V024_MID_NONSECURE_WDT" or dict(recomputed) != dict(signature):
        raise FinalizeError("last-kmsg binary does not recompute the exact public signature")
    journal, journal_bytes, _ = _json(journal_path, root=root / PRIVATE_ROOT_NAME, label="last-kmsg journal")
    if journal.get("schema") != "sdm855-a90-last-kmsg-capture-private-v2" or journal.get("experiment_id") != experiment_id or journal.get("status") != "COMPLETE" or journal.get("target_verified") is not True or journal.get("effect_dispatched") is not False or journal.get("effect_replayed") is not False or journal.get("last_kmsg_read_once") is not True or journal.get("private_record") != metadata_name or journal.get("raw_filename") != raw_name or journal.get("captured_log_filename") != captured_name or journal.get("retained_sha256") != hashlib.sha256(signature_bytes).hexdigest() or journal.get("retained_size") != len(signature_bytes) or journal.get("captured_log_sha256") != captured_hash or journal.get("captured_log_size") != len(captured_bytes):
        raise FinalizeError("last-kmsg journal is not complete/hash-bound")
    if journal.get("records") != metadata_records:
        raise FinalizeError("last-kmsg journal transport records differ from metadata")
    if journal.get("read_source") != dict(source_summary) or journal.get("source_pre_read_boot_id") != source_summary.get("source_pre_read_boot_id") or journal.get("current_boot_id") != metadata_current_boot or journal.get("current_boot_id_sha256") != current_boot_hash or journal.get("boot_id_changed") is not True:
        raise FinalizeError("last-kmsg journal boot/source join is not exact")
    _validate_last_stophud(value, metadata, journal)
    completed = public_completed
    if _utc(journal.get("completed_utc"), "last-kmsg journal") != completed:
        raise FinalizeError("last-kmsg completion times differ")
    return {"kind": "last_kmsg", "experiment_id": experiment_id, "path": str(checked), **_receipt_hash(data), "delta_seconds": number, "completed_utc": value["completed_utc"], "raw_sha256": captured_hash, "raw_size": len(captured_bytes), "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(), "signature_size": len(signature_bytes), "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(), "journal_sha256": hashlib.sha256(journal_bytes).hexdigest(), "read_source": dict(source), "source_pre_read_boot_id_sha256": value.get("source_pre_read_boot_id_sha256"), "current_boot_id_sha256": current_boot_hash}


def _parse_signature_bytes(data: bytes) -> tuple[dict[str, object], dict[str, object]]:
    try:
        parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalizeError("last-kmsg raw signature is not strict JSON") from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"exact_reset_signature"}
        or not isinstance(parsed.get("exact_reset_signature"), Mapping)
    ):
        raise FinalizeError("last-kmsg raw signature lacks exact_reset_signature")
    return dict(parsed["exact_reset_signature"]), parsed


def _validate_fixed_read_source(
    root: Path, source_experiment_id: str = READ_SOURCE_EXPERIMENT_ID
) -> dict[str, object]:
    """Validate the exact fixed read receipt joined to last-kmsg evidence."""

    if source_experiment_id != READ_SOURCE_EXPERIMENT_ID:
        raise FinalizeError("read source experiment ID is not the fixed V024 source")
    source_manifest_name = f"{source_experiment_id}.manifest.json"
    source_raw_name = f"{source_experiment_id}.json"
    source_journal_name = f"{source_experiment_id}.journal.json"

    manifest_path = root / MANIFEST_ROOT_NAME / source_manifest_name
    raw_path = root / PRIVATE_ROOT_NAME / source_raw_name
    journal_path = root / PRIVATE_ROOT_NAME / source_journal_name
    manifest, manifest_bytes, _ = _json(
        manifest_path, root=root / MANIFEST_ROOT_NAME, label="read source manifest"
    )
    raw, raw_bytes, _ = _json(raw_path, root=root / PRIVATE_ROOT_NAME, label="read source raw")
    journal, journal_bytes, _ = _json(
        journal_path, root=root / PRIVATE_ROOT_NAME, label="read source journal"
    )
    _require(manifest, "schema", "sdm855-a90-inline-remapper-mid-public-v1", "read source manifest")
    _require(manifest, "experiment_id", source_experiment_id, "read source manifest")
    _require(manifest, "mode", "read", "read source manifest")
    for key, expected in {
        "candidate_sha256": READ_SHA256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "target_verified": True,
        "target_evaluation": "VERIFIED",
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": TARGET_RUNTIME,
        "outcome": "REFUSED_AT_MID_CANDIDATE",
        "dispatch_count": 1,
        "effect_dispatched": True,
        "effect_ambiguous": True,
        "effect_replayed": False,
        "dispatch_returned": False,
        "dispatch_failed": True,
        "automatic_retries": False,
        "returned_value_present": False,
        "returned_value_sha256": None,
        "panic_on_oops_before": 1,
        "panic_on_oops_zero_set": True,
        "panic_on_oops_zero_verified": True,
        "panic_on_oops_restored": False,
        "panic_restore_deferred": True,
        "health_after_ok": False,
        "transport_no_value": True,
        "cleanup_ok": False,
        "flash_profile": "read",
        "flash_image_sha256": READ_SHA256,
        "flash_readback_sha256": READ_SHA256,
        "flash_predecessor_sha256": CONTROL_SHA256,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
    }.items():
        _require(manifest, key, expected, "read source manifest")
    manifest_attestation = _validate_current_boot_attestation(
        manifest.get("current_boot_attestation"),
        READ_SHA256,
        "read source manifest",
        require_paths=False,
    )
    fixed_public = manifest.get("fixed_op")
    if not isinstance(fixed_public, Mapping):
        raise FinalizeError("read source fixed_op is missing")
    if set(fixed_public) != {
        "op",
        "args",
        "buffer_size",
        "buffer_sha256",
        "rc",
        "status",
        "value",
    }:
        raise FinalizeError("read source public fixed_op fields are not exact")
    for key, expected in {
        "op": 4,
        "args": [],
        "buffer_size": 0x58,
        "buffer_sha256": _fixed_op_buffer_hash(),
    }.items():
        _require(fixed_public, key, expected, "read source fixed_op")
    for key, expected in {"rc": None, "status": None, "value": None}.items():
        _require(fixed_public, key, expected, "read source fixed_op")
    expected_transition = {
        "before": 1,
        "zero_write_attempted": True,
        "zero_set": True,
        "zero_verified": True,
        "restore_write_attempted": False,
        "restored": False,
        "restore_deferred": True,
        "proof_frame_ids": ["panic_before", "panic_set_0", "panic_zero_verify"],
    }
    if manifest.get("panic_transition") != expected_transition:
        raise FinalizeError("read source panic transition is not exact")
    source_private = manifest.get("private_record")
    if not isinstance(source_private, Mapping) or source_private.get("filename") != source_raw_name or source_private.get("journal_filename") != source_journal_name:
        raise FinalizeError("read source private filenames are not fixed")
    if manifest.get("raw_snapshot_sha256") != hashlib.sha256(raw_bytes).hexdigest() or manifest.get("raw_snapshot_size") != len(raw_bytes) or manifest.get("journal_sha256") != hashlib.sha256(journal_bytes).hexdigest() or manifest.get("journal_size") != len(journal_bytes):
        raise FinalizeError("read source public/private hash binding is not exact")
    _require(raw, "schema", "sdm855-a90-inline-remapper-mid-private-v1", "read source raw")
    _require(raw, "experiment_id", source_experiment_id, "read source raw")
    _require(raw, "mode", "read", "read source raw")
    for key, expected in {
        "candidate_sha256": READ_SHA256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "outcome": "REFUSED_AT_MID_CANDIDATE",
        "dispatch_count": 1,
        "effect_dispatched": True,
        "effect_ambiguous": True,
        "effect_replayed": False,
        "dispatch_returned": False,
        "dispatch_failed": True,
        "panic_on_oops_before": 1,
        "panic_on_oops_zero_set": True,
        "panic_on_oops_zero_verified": True,
        "panic_on_oops_restored": False,
        "panic_restore_deferred": True,
        "cleanup_ok": False,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
    }.items():
        _require(raw, key, expected, "read source raw")
    _require_inline_target(raw.get("target"), "read source raw target")
    read_flash_binding = _validate_flash_reference(
        raw.get("flash_journal"),
        profile="read",
        expected_predecessor=CONTROL_SHA256,
        root=root,
        label="read source raw",
    )
    _require(raw, "panic_transition", expected_transition, "read source raw")
    _require(raw, "fixed_op_measurement", None, "read source raw")
    control_binding = raw.get("control_manifest")
    if not isinstance(control_binding, Mapping):
        raise FinalizeError("read source raw control binding is missing")
    for key, expected in {
        "mode": "control",
        "candidate_sha256": CONTROL_SHA256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "value": "0x000000000000c071",
        "target_dmid": TARGET_DMID,
        "predecessor_capsule_sha256": CONTROL_R2_PREDECESSOR_CAPSULE_SHA256,
        "predecessor_capsule_size": CONTROL_R2_PREDECESSOR_CAPSULE_SIZE,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
    }.items():
        _require(control_binding, key, expected, "read source raw control binding")
    for key in ("experiment_id", "manifest_sha256", "raw_sha256", "journal_sha256", "boot_id_before_read_sha256"):
        if key not in control_binding:
            raise FinalizeError(f"read source raw control binding {key!r} is missing")
    _validate_current_boot_attestation(
        control_binding.get("current_boot_attestation"),
        CONTROL_SHA256,
        "read source control attestation",
        require_paths=False,
    )
    _validate_fixed_measurement(
        control_binding.get("fixed_op_measurement"),
        "0x000000000000c071",
        "read source control fixed-op",
    )
    # Re-open the exact control manifest named by the source binding.  A
    # copied/reformatted control summary must not mint a new read namespace,
    # and the read flash completion must be strictly later than that verified
    # control completion.
    control_id = control_binding.get("experiment_id")
    if not isinstance(control_id, str) or SAFE_ID_RE.fullmatch(control_id) is None:
        raise FinalizeError("read source control experiment ID is not exact")
    try:
        control_summary = validate_control(
            root / MANIFEST_ROOT_NAME / f"{control_id}.manifest.json", root
        )
        read_flash_source = verify_flash_journal(
            Path(str(read_flash_binding.get("path"))), "read", root=root
        )
        control_completed = _utc(control_summary.get("completed_utc"), "read source control")
        read_flash_completed = _utc(
            read_flash_source.get("record", {}).get("completed_utc")
            if isinstance(read_flash_source.get("record"), Mapping)
            else None,
            "read source flash journal",
        )
    except BaseException as exc:
        raise FinalizeError("read source control/flash chronology cannot be validated") from exc
    if control_binding.get("current_boot_attestation") != control_summary.get(
        "current_boot_attestation"
    ):
        raise FinalizeError(
            "read source control attestation projection differs from validated control"
        )
    for key in (
        "experiment_id",
        "manifest_sha256",
        "manifest_size",
        "raw_sha256",
        "raw_size",
        "journal_sha256",
        "journal_size",
        "completed_utc",
        "candidate_sha256",
        "candidate_size",
        "value",
        "target_dmid",
        "boot_id_before_read_sha256",
        "predecessor_capsule_sha256",
        "predecessor_capsule_size",
        "r2_incident_manifest_sha256",
        "r2_incident_manifest_size",
        "r2_zero_effect_validated",
        "r3_incident_manifest_sha256",
        "r3_incident_manifest_size",
        "r3_zero_op_restored_validated",
    ):
        if type(control_binding.get(key)) is not type(control_summary.get(key)) or control_binding.get(key) != control_summary.get(key):
            raise FinalizeError(f"read source control binding field {key!r} differs")
    if read_flash_completed <= control_completed:
        raise FinalizeError(
            "read source flash receipt must complete strictly after control receipt"
        )
    read_completed = _utc(manifest.get("completed_utc"), "read source manifest")
    if read_flash_completed >= read_completed:
        raise FinalizeError(
            "read source flash receipt must complete before the read probe receipt"
        )
    raw_attestation = _validate_current_boot_attestation(
        raw.get("current_boot_attestation"), READ_SHA256, "read source raw"
    )
    for key in (
        "captured_sha256",
        "captured_size",
        "expected_sha256",
        "expected_size",
        "cleanup_ok",
        "sysfs_uevent",
        "stat",
    ):
        if raw_attestation.get(key) != manifest_attestation.get(key):
            raise FinalizeError(
                f"read source current-boot attestation {key!r} differs"
            )
    source_boot_id = _validate_boot_id_binding(manifest, raw, journal, "read source")
    _validate_semantic_claim(
        manifest,
        raw,
        journal,
        root=root,
        mode="read",
        candidate_sha256=READ_SHA256,
        label="read source",
    )
    _validate_transport_no_value(raw.get("error"), "read source transport")
    if raw.get("error") != journal.get("error"):
        raise FinalizeError("read source raw/journal transport errors differ")
    _validate_frame_list(
        raw.get("frames"), "read source raw", restored=False, allow_fixed=False,
        include_health=False,
    )
    _validate_frame_list(
        journal.get("frames"), "read source journal", restored=False,
        allow_fixed=False, include_health=False,
    )
    _require_panic_frames_equal(raw.get("frames"), journal.get("frames"), "read source")
    source_target = raw.get("target")
    if not isinstance(source_target, Mapping):
        raise FinalizeError("read source raw target is missing")
    _validate_inline_frame_payload_semantics(
        raw.get("frames"),
        target=source_target,
        attestation=raw_attestation,
        candidate_sha256=READ_SHA256,
        candidate_size=BOOT_PREFIX_SIZE,
        boot_id_before_read=source_boot_id,
        label="read source raw",
        include_health=False,
    )
    _require(journal, "schema", "sdm855-a90-inline-remapper-mid-journal-v1", "read source journal")
    _require(journal, "experiment_id", source_experiment_id, "read source journal")
    _require(journal, "mode", "read", "read source journal")
    _require_hash(journal.get("candidate_sha256"), READ_SHA256, "read source journal candidate")
    _require_size(journal.get("candidate_size"), BOOT_PREFIX_SIZE, "read source journal candidate")
    _require(journal, "op", 4, "read source journal")
    _require(journal, "op_args", [], "read source journal")
    _require(journal, "status", "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED", "read source journal")
    _require_inline_target(journal.get("target"), "read source journal target")
    journal_fixed = journal.get("fixed_op")
    if not isinstance(journal_fixed, Mapping):
        raise FinalizeError("read source journal fixed_op is missing")
    if set(journal_fixed) != {
        "op",
        "args",
        "buffer_size",
        "buffer_sha256",
    }:
        raise FinalizeError("read source journal fixed_op fields are not exact")
    for key, expected in {
        "op": 4,
        "args": [],
        "buffer_size": 0x58,
        "buffer_sha256": _fixed_op_buffer_hash(),
    }.items():
        _require(journal_fixed, key, expected, "read source journal fixed_op")
    for key, expected in {
        "outcome": "REFUSED_AT_MID_CANDIDATE",
        "dispatch_count": 1,
        "effect_dispatched": True,
        "effect_ambiguous": True,
        "effect_replayed": False,
        "dispatch_returned": False,
        "dispatch_failed": True,
        "panic_on_oops_before": 1,
        "panic_on_oops_zero_set": True,
        "panic_on_oops_zero_verified": True,
        "panic_on_oops_restored": False,
        "panic_restore_deferred": True,
        "cleanup_ok": False,
        "r2_incident_manifest_sha256": CONTROL_R2_INCIDENT_MANIFEST_SHA256,
        "r2_incident_manifest_size": CONTROL_R2_INCIDENT_MANIFEST_SIZE,
        "r2_zero_effect_validated": True,
        "r3_incident_manifest_sha256": CONTROL_R3_INCIDENT_MANIFEST_SHA256,
        "r3_incident_manifest_size": CONTROL_R3_INCIDENT_MANIFEST_SIZE,
        "r3_zero_op_restored_validated": True,
    }.items():
        _require(journal, key, expected, "read source journal")
    _require(journal, "panic_transition", expected_transition, "read source journal")
    if not isinstance(journal.get("control_manifest"), Mapping) or dict(journal["control_manifest"]) != dict(control_binding):
        raise FinalizeError("read source journal control binding differs")
    if not isinstance(journal.get("flash_journal"), Mapping) or dict(journal["flash_journal"]) != dict(raw["flash_journal"]):
        raise FinalizeError("read source journal flash binding differs")
    journal_attestation = _validate_current_boot_attestation(
        journal.get("current_boot_attestation"), READ_SHA256, "read source journal"
    )
    for key in (
        "captured_sha256",
        "captured_size",
        "expected_sha256",
        "expected_size",
        "cleanup_ok",
        "sysfs_uevent",
        "stat",
    ):
        if journal_attestation.get(key) != raw_attestation.get(key):
            raise FinalizeError(
                f"read source journal current-boot attestation {key!r} differs"
            )
    source_journal_target = journal.get("target")
    if not isinstance(source_journal_target, Mapping):
        raise FinalizeError("read source journal target is missing")
    _validate_inline_frame_payload_semantics(
        journal.get("frames"),
        target=source_journal_target,
        attestation=journal_attestation,
        candidate_sha256=READ_SHA256,
        candidate_size=BOOT_PREFIX_SIZE,
        boot_id_before_read=source_boot_id,
        label="read source journal",
        include_health=False,
    )
    completed = read_completed
    if _utc(raw.get("completed_utc"), "read source raw") != completed or _utc(journal.get("completed_utc"), "read source journal") != completed:
        raise FinalizeError("read source completion times differ")
    return {
        "experiment_id": source_experiment_id,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "manifest_size": len(manifest_bytes),
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "raw_size": len(raw_bytes),
        "journal_sha256": hashlib.sha256(journal_bytes).hexdigest(),
        "journal_size": len(journal_bytes),
        "completed_utc": manifest["completed_utc"],
        "source_pre_read_boot_id_sha256": manifest.get("boot_id_before_read_sha256"),
        "source_pre_read_boot_id": raw.get("boot_id_before_read"),
    }


def validate_rollback_flash(path: Path, root: Path) -> dict[str, object]:
    value, data, checked = _load_public_or_private(path, root / PRIVATE_ROOT_NAME, "rollback flash")
    if value.get("schema") in {
        "sdm855-a90-boot-torn-rollback-recovery-private-v1",
        "sdm855-a90-boot-torn-rollback-recovery-public-v1",
    }:
        expected_torn = (
            root
            / PRIVATE_ROOT_NAME
            / "verification-024-boot-torn-rollback-torn-final.journal.json"
        ).resolve(strict=False)
        if checked != expected_torn:
            raise FinalizeError("boot-torn rollback path is not the fixed V024 recovery producer")
        return _validate_torn_rollback(value, data, checked, root)
    if value.get("schema") != "sdm855-a90-remapper-boot-flash-private-v1":
        raise FinalizeError("rollback flash schema is not exact")
    expected_normal = (
        root / PRIVATE_ROOT_NAME / FLASH_JOURNAL_NAMES["rollback"]
    ).resolve(strict=False)
    if checked != expected_normal:
        raise FinalizeError("rollback flash path is not the fixed V024 rollback producer")
    for key, expected in {
        "profile": "rollback",
        "status": "PASS_READBACK_AND_CLEANUP",
        "write_count": 1,
        "effect_dispatched": True,
        "effect_armed": True,
        "partition_writes": True,
        "staging_removed": True,
        "staging_cleanup_deferred": False,
        "pre_staging_removed": True,
        "pre_cleanup_error": None,
        "reboot_dispatched": False,
        "cleanup_error": None,
        "error": None,
        "target_model": TARGET_MODEL,
        "target_device": TARGET_DEVICE,
        "target_serial_sha256": TARGET_SERIAL_SHA256,
        "boot_alias": "/dev/block/by-name/boot",
        "boot_node": "/dev/block/sda24",
        "post_staging_revalidated": True,
        "post_staging_predecessor_revalidated": True,
        "pre_cleanup_revalidated": True,
        "pre_push_revalidated": True,
        "pre_effect_revalidated": True,
        "post_dispatch_revalidated": True,
        "final_revalidated": True,
        "final_cleanup_revalidated": True,
    }.items():
        _require(value, key, expected, "rollback flash")
    for key in ("image_sha256", "remote_staging_sha256", "readback_sha256", "post_dispatch_staging_sha256"):
        _require_hash(value.get(key), ROLLBACK_SHA256, f"rollback flash {key}")
    for key in ("image_size", "remote_staging_size", "readback_size", "post_dispatch_staging_size", "predecessor_size"):
        _require_size(value.get(key), BOOT_PREFIX_SIZE, f"rollback flash {key}")
    for key in ("post_staging_predecessor_size", "post_dispatch_predecessor_size"):
        _require_size(value.get(key), BOOT_PREFIX_SIZE, f"rollback flash {key}")
    for key in (
        "pre_cleanup_target_serial_sha256",
        "pre_push_target_serial_sha256",
        "post_staging_target_serial_sha256",
        "pre_effect_target_serial_sha256",
        "post_dispatch_target_serial_sha256",
        "final_target_serial_sha256",
        "final_cleanup_target_serial_sha256",
    ):
        _require_hash(value.get(key), TARGET_SERIAL_SHA256, f"rollback flash {key}")
    # Older successful journals used the shorter rebind aliases while newer
    # ones retain both aliases and phase-specific target fields.  If an alias
    # is present, it is still part of the claimed binding and must carry the
    # exact same A90 serial hash; never silently ignore a conflicting copy.
    for alias in (
        "post_staging_rebind_serial_sha256",
        "pre_effect_rebind_serial_sha256",
        "post_dispatch_rebind_serial_sha256",
        "final_rebind_serial_sha256",
    ):
        if alias in value:
            _require_hash(value.get(alias), TARGET_SERIAL_SHA256, f"rollback flash {alias}")
    allowed = value.get("allowed_predecessors")
    if allowed != ROLLBACK_ALLOWED_PREDECESSORS:
        raise FinalizeError("rollback flash predecessor set is not exact")
    predecessor = value.get("predecessor_sha256")
    if predecessor != READ_SHA256:
        raise FinalizeError("final rollback must prove the READ_SHA256 predecessor")
    if value.get("post_staging_predecessor_sha256") != predecessor:
        raise FinalizeError("rollback flash post-staging predecessor differs")
    if value.get("post_dispatch_predecessor_sha256") != predecessor:
        raise FinalizeError("rollback flash post-dispatch predecessor differs")
    if value.get("remote_staging") != FLASH_REMOTE_STAGING["rollback"]:
        raise FinalizeError("rollback flash staging path is not the fixed rollback producer")
    effect_argv = value.get("effect_argv")
    expected_effect_argv = _fixed_flash_effect_argv("rollback")
    if effect_argv != expected_effect_argv:
        raise FinalizeError("rollback flash effect argv is not exact")
    _validate_guarded_effect_receipt(
        value.get("guarded_effect_receipt"),
        profile="rollback",
        predecessor=predecessor,
        label="rollback flash",
    )
    completed = _utc(value.get("completed_utc"), "rollback flash")
    return {"kind": "rollback_flash", "path": str(checked), **_receipt_hash(data), "completed_utc": value["completed_utc"], "predecessor_sha256": predecessor}


def _source_semantic_identity(
    root: Path, profile: str, predecessor: str
) -> tuple[dict[str, object], str]:
    """Derive the boot worker's canonical source identity.

    The raw JSON digest is only a byte-level receipt binding.  The recovery
    worker's one-way claim is keyed to this fixed source path and semantic
    profile instead, so reformatting the same journal cannot create a second
    causal source namespace.
    """

    if profile != "rollback" or predecessor != READ_SHA256:
        raise FinalizeError("final rollback source semantic profile is not the fixed rollback/READ edge")
    source_path = (
        root
        / PRIVATE_ROOT_NAME
        / FLASH_JOURNAL_NAMES["rollback"]
    )
    remote_staging = FLASH_REMOTE_STAGING["rollback"]
    effect_argv = _fixed_flash_effect_argv("rollback")
    identity: dict[str, object] = {
        "schema": "sdm855-a90-remapper-boot-flash-private-v1",
        "source_journal_path": str(source_path),
        "profile": "rollback",
        "allowed_predecessors": list(ROLLBACK_ALLOWED_PREDECESSORS),
        "predecessor_sha256": READ_SHA256,
        "predecessor_size": BOOT_PREFIX_SIZE,
        "image_sha256": ROLLBACK_SHA256,
        "image_size": BOOT_PREFIX_SIZE,
        "remote_staging": remote_staging,
        "remote_staging_sha256": ROLLBACK_SHA256,
        "remote_staging_size": BOOT_PREFIX_SIZE,
        "post_staging_predecessor_sha256": READ_SHA256,
        "post_staging_predecessor_size": BOOT_PREFIX_SIZE,
        "effect_argv": effect_argv,
    }
    canonical = _runtime_json_bytes(identity)
    return identity, hashlib.sha256(canonical).hexdigest()


def _validate_ambiguous_source(
    source: Mapping[str, object],
    label: str,
    *,
    source_path: Path | None = None,
    root: Path | None = None,
) -> dict[str, object]:
    """Validate the exact source contract consumed by boot-torn recovery.

    This is the retained ambiguous-source contract from
    ``a90_twrp_boot_rollback_recovery._validate_source``.  It requires the
    producer's complete pre-effect staging/predecessor proof, while allowing
    post-dispatch guard projections only when the producer actually returned
    that receipt.  An ambiguous transport must never acquire fabricated
    readback or guard fields.
    """

    profile_hashes = {"control": CONTROL_SHA256, "read": READ_SHA256, "rollback": ROLLBACK_SHA256}
    if source.get("schema") != "sdm855-a90-remapper-boot-flash-private-v1" or source.get("status") != "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED":
        raise FinalizeError(f"{label} is not an ambiguous V024 flash journal")
    for key, expected in {
        "target_model": TARGET_MODEL,
        "target_device": TARGET_DEVICE,
        "target_serial_sha256": TARGET_SERIAL_SHA256,
        "boot_alias": "/dev/block/by-name/boot",
        "boot_node": "/dev/block/sda24",
        "effect_armed": True,
        "effect_dispatched": True,
        "effect_ambiguous": True,
        "effect_replayed": False,
        "automatic_retries": False,
        "reboot_dispatched": False,
        "write_count": 1,
        "partition_writes": True,
        "staging_attempted": True,
        "staging_attempt_count": 1,
        "staging_dispatch_count": 1,
        "staging_status": "STAGING_PUSH_RETURNED",
        "pre_staging_removed": True,
        "pre_cleanup_revalidated": True,
        "pre_push_revalidated": True,
        "staging_removed": False,
        "post_staging_revalidated": True,
        "post_staging_predecessor_revalidated": True,
        "pre_effect_revalidated": True,
        "current_state": "UNKNOWN",
        "staging_cleanup_deferred": True,
        "reconcile_required": True,
        "predecessor_size": BOOT_PREFIX_SIZE,
    }.items():
        _require(source, key, expected, label)
    profile = source.get("profile")
    if profile != "rollback":
        raise FinalizeError(f"{label} final rollback source must be the rollback profile")
    _require(
        source,
        "allowed_predecessors",
        ROLLBACK_ALLOWED_PREDECESSORS,
        f"{label} allowed predecessors",
    )
    _require_hash(source.get("image_sha256"), profile_hashes[profile], f"{label} image")
    _require_size(source.get("image_size"), BOOT_PREFIX_SIZE, f"{label} image")
    _require_hash(
        source.get("remote_staging_sha256"),
        profile_hashes[profile],
        f"{label} remote staging",
    )
    _require_size(
        source.get("remote_staging_size"), BOOT_PREFIX_SIZE, f"{label} remote staging"
    )
    expected_effect_argv = _fixed_flash_effect_argv("rollback")
    _require(source, "remote_staging", FLASH_REMOTE_STAGING["rollback"], f"{label} remote staging")
    if source.get("effect_argv") != expected_effect_argv:
        raise FinalizeError(f"{label} effect argv is not fixed")
    predecessor = source.get("predecessor_sha256")
    if predecessor != READ_SHA256:
        raise FinalizeError(f"{label} rollback-source predecessor must be READ_SHA256")
    if source.get("post_staging_predecessor_sha256") != predecessor:
        raise FinalizeError(f"{label} post-staging predecessor differs")
    _require_size(
        source.get("post_staging_predecessor_size"),
        BOOT_PREFIX_SIZE,
        f"{label} post-staging predecessor",
    )
    projection_keys = (
        "post_dispatch_predecessor_sha256",
        "post_dispatch_predecessor_size",
        "post_dispatch_staging_sha256",
        "post_dispatch_staging_size",
    )
    guarded = source.get("guarded_effect_receipt")
    if guarded is None:
        if any(key in source for key in projection_keys):
            raise FinalizeError(f"{label} post-dispatch projection lacks guarded receipt")
    else:
        _validate_guarded_effect_receipt(
            guarded,
            profile="rollback",
            predecessor=predecessor,
            label=f"{label} guarded effect",
        )
        expected_projection = {
            "post_dispatch_predecessor_sha256": predecessor,
            "post_dispatch_predecessor_size": BOOT_PREFIX_SIZE,
            "post_dispatch_staging_sha256": ROLLBACK_SHA256,
            "post_dispatch_staging_size": BOOT_PREFIX_SIZE,
        }
        if any(source.get(key) != expected for key, expected in expected_projection.items()):
            raise FinalizeError(f"{label} post-dispatch projections differ")
    if source_path is not None:
        if root is None:
            raise FinalizeError(f"{label} fixed source root is missing")
        expected_path = (
            root
            / PRIVATE_ROOT_NAME
            / FLASH_JOURNAL_NAMES["rollback"]
        ).resolve(strict=False)
        if source_path.resolve(strict=False) != expected_path:
            raise FinalizeError(f"{label} source path is not the fixed rollback journal")
    identity_root = root if root is not None else REPO_ROOT
    semantic_identity, semantic_sha256 = _source_semantic_identity(
        identity_root, str(profile), str(predecessor)
    )
    return {
        "profile": profile,
        "image_sha256": profile_hashes[profile],
        "predecessor_sha256": predecessor,
        "semantic_identity": semantic_identity,
        "semantic_sha256": semantic_sha256,
    }


def _validate_torn_rollback(value: Mapping[str, object], data: bytes, checked: Path, root: Path) -> dict[str, object]:
    """Validate the actual boot-torn recovery producer's private/public pair."""

    expected_torn_path = (
        root
        / PRIVATE_ROOT_NAME
        / "verification-024-boot-torn-rollback-torn-final.journal.json"
    ).resolve(strict=False)
    if checked.resolve(strict=False) != expected_torn_path:
        raise FinalizeError("boot-torn rollback path is not the fixed torn-final producer")
    if value.get("schema") != "sdm855-a90-boot-torn-rollback-recovery-private-v1":
        raise FinalizeError("boot-torn rollback must be supplied as its private journal")
    experiment_id = _experiment_id(value, "boot-torn rollback")
    if experiment_id != TORN_ROLLBACK_EXPERIMENT_ID:
        raise FinalizeError(
            "boot-torn rollback experiment ID is not the fixed torn-final producer"
        )
    status = value.get("status")
    if status not in {"PASS_ROLLBACK_READBACK_AND_CLEANUP", "PASS_ALREADY_ROLLBACK_AND_CLEANUP"}:
        raise FinalizeError("boot-torn rollback terminal status is not exact PASS")
    if value.get("effect_replayed") is not False or type(value.get("partition_writes")) is not bool:
        raise FinalizeError("boot-torn rollback replay/write fields are not exact")
    target = value.get("target")
    if not isinstance(target, Mapping):
        raise FinalizeError("boot-torn rollback target is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "device": TARGET_DEVICE,
        "twrp_version": "3.7.0_12-0",
        "serial_sha256": TARGET_SERIAL_SHA256,
    }.items():
        _require(target, key, expected, "boot-torn rollback target")
    _require(value, "target_verified", True, "boot-torn rollback")
    _require(value, "rollback_image_sha256", ROLLBACK_SHA256, "boot-torn rollback image")
    _require_size(value.get("rollback_image_size"), BOOT_PREFIX_SIZE, "boot-torn rollback image")
    _require(value, "boot_alias", "/dev/block/by-name/boot", "boot-torn rollback")
    _require(value, "boot_node", "/dev/block/sda24", "boot-torn rollback")
    _require(value, "cleanup_proved", True, "boot-torn rollback cleanup")
    if value.get("cleanup_error") not in {None, ""}:
        raise FinalizeError("boot-torn rollback cleanup error is present")
    write_count = value.get("write_count")
    if type(write_count) is not int or write_count not in {0, 1}:
        raise FinalizeError("boot-torn rollback write_count is not exact")
    if value.get("partition_writes") is not (write_count == 1):
        raise FinalizeError("boot-torn rollback partition-write summary is not exact")
    if status == "PASS_ALREADY_ROLLBACK_AND_CLEANUP":
        if write_count != 0 or value.get("current_pre_hash_sha256") != ROLLBACK_SHA256 or value.get("current_pre_hash_size") != BOOT_PREFIX_SIZE:
            raise FinalizeError("already-rollback terminal is not zero-write exact")
    else:
        if write_count != 1 or value.get("effect_dispatched") is not True or value.get("effect_armed") is not True:
            raise FinalizeError("one-write torn rollback terminal is not exact")
        if value.get("readback_sha256") != ROLLBACK_SHA256 or value.get("readback_size") != BOOT_PREFIX_SIZE:
            raise FinalizeError("torn rollback readback is not exact")
    current_pre_hash = value.get("current_pre_hash_sha256")
    current_pre_size = value.get("current_pre_hash_size")
    if not isinstance(current_pre_hash, str) or SHA256_RE.fullmatch(current_pre_hash) is None or type(current_pre_size) is not int or current_pre_size != BOOT_PREFIX_SIZE:
        raise FinalizeError("torn rollback current preimage hash/size is missing")
    source_path_value = value.get("source_flash_journal_path")
    source_hash = value.get("source_flash_journal_sha256")
    source_size = value.get("source_flash_journal_size")
    if not isinstance(source_path_value, str) or not isinstance(source_hash, str) or SHA256_RE.fullmatch(source_hash) is None or type(source_size) is not int or source_size <= 0:
        raise FinalizeError("torn rollback source journal reference is malformed")
    expected_source_path = (
        root / PRIVATE_ROOT_NAME / FLASH_JOURNAL_NAMES["rollback"]
    ).resolve(strict=False)
    try:
        supplied_source_path = Path(source_path_value)
        if not supplied_source_path.is_absolute():
            supplied_source_path = root / supplied_source_path
        _reject_symlink_components(supplied_source_path, "torn rollback source journal")
        supplied_source_path = supplied_source_path.resolve(strict=False)
    except (TypeError, ValueError, OSError) as exc:
        raise FinalizeError("torn rollback source journal path is not fixed") from exc
    if supplied_source_path != expected_source_path or source_path_value != str(expected_source_path):
        raise FinalizeError("torn rollback source journal path is not the fixed rollback journal")
    source_path = _path_under(Path(source_path_value), root / PRIVATE_ROOT_NAME, "torn rollback source journal")
    source, source_data, _ = _json(source_path, root=root / PRIVATE_ROOT_NAME, label="torn rollback source journal")
    if len(source_data) != source_size or hashlib.sha256(source_data).hexdigest() != source_hash:
        raise FinalizeError("torn rollback source journal hash/size changed")
    source_contract = _validate_ambiguous_source(
        source,
        "torn rollback source journal",
        source_path=source_path,
        root=root,
    )
    for key, expected in {
        "source_semantic_sha256": source_contract["semantic_sha256"],
        "source_consumption_claim_key_sha256": source_contract["semantic_sha256"],
        "source_semantic_identity": source_contract["semantic_identity"],
        "source_profile": "rollback",
    }.items():
        _require(value, key, expected, "boot-torn rollback source semantic binding")
    source_identity = value.get("source_flash_journal_identity")
    if not isinstance(source_identity, Mapping):
        raise FinalizeError("boot-torn rollback source journal identity is missing")
    source_stat = source_path.stat()
    expected_source_identity = {
        "st_dev": source_stat.st_dev,
        "st_ino": source_stat.st_ino,
        "st_mode": source_stat.st_mode,
        "st_size": source_stat.st_size,
        "st_mtime_ns": source_stat.st_mtime_ns,
        "st_ctime_ns": source_stat.st_ctime_ns,
        "sha256": source_hash,
    }
    for key, expected in expected_source_identity.items():
        _require(
            source_identity,
            key,
            expected,
            "boot-torn rollback source journal identity",
        )
    public_path = _manifest_path(
        root
        / MANIFEST_ROOT_NAME
        / "verification-024-boot-torn-rollback-torn-final.manifest.json",
        root,
        "torn rollback public manifest",
    )
    public, public_data, _ = _json(public_path, root=root / MANIFEST_ROOT_NAME, label="torn rollback public manifest")
    if public.get("schema") != "sdm855-a90-boot-torn-rollback-recovery-public-v1" or public.get("experiment_id") != experiment_id:
        raise FinalizeError("torn rollback public counterpart is not exact")
    if public.get("private_receipt_sha256") != hashlib.sha256(data).hexdigest() or public.get("private_receipt_size") != len(data):
        raise FinalizeError("torn rollback private/public hash binding is not exact")
    if public.get("current_pre_hash_sha256") != current_pre_hash or public.get("current_pre_hash_size") != current_pre_size:
        raise FinalizeError("torn rollback public/private preimage binding differs")

    # The recovery producer reserves a shared physical preimage claim before
    # cleanup/staging/effect.  Validate that exact claim receipt as part of
    # the final rollback predecessor proof; source-consumption alone is not a
    # substitute for the physical no-replay lock.
    try:
        effect_identity, effect_key_sha256 = boot_prefix_claim_identity(
            current_pre_hash, current_pre_size
        )
        effect_claim_path = boot_prefix_claim_path(root, effect_key_sha256).resolve(
            strict=False
        )
    except (TypeError, ValueError, OSError) as exc:
        raise FinalizeError("torn rollback physical claim identity is malformed") from exc
    physical = value.get("physical_effect_claim")
    if not isinstance(physical, Mapping):
        raise FinalizeError("torn rollback private physical effect claim is missing")
    expected_claim_terminal = (
        "before_zero_write_cleanup" if write_count == 0 else "before_recovery_effect_marker"
    )
    for key, expected in {
        "attempted": True,
        "claimed": True,
        "key_sha256": effect_key_sha256,
        "claim_path": str(effect_claim_path),
        "terminal": expected_claim_terminal,
    }.items():
        _require(physical, key, expected, "torn rollback private physical effect claim")
    claim_hash = physical.get("claim_sha256")
    claim_size = physical.get("claim_size")
    if not isinstance(claim_hash, str) or SHA256_RE.fullmatch(claim_hash) is None or type(claim_size) is not int or claim_size <= 0 or claim_size > MAX_RECEIPT_BYTES:
        raise FinalizeError("torn rollback physical claim hash/size is malformed")
    claim, claim_bytes, _ = _json(
        effect_claim_path,
        root=root / PRIVATE_ROOT_NAME,
        label="torn rollback physical effect claim",
    )
    if hashlib.sha256(claim_bytes).hexdigest() != claim_hash or len(claim_bytes) != claim_size:
        raise FinalizeError("torn rollback physical claim hash/size differs")
    # Continuation provenance belongs to the private physical-claim section
    # in the recovery producer.  A top-level copy is not part of that schema
    # and must not be allowed to steer owner selection.
    if "continued_from_normal_ambiguous" in value:
        raise FinalizeError("boot-torn rollback continuation flag is misplaced")
    physical_continuation = value.get("physical_effect_claim")
    if not isinstance(physical_continuation, Mapping):
        raise FinalizeError("boot-torn rollback private physical effect claim is missing")
    continued_field = physical_continuation.get("continued_from_normal_ambiguous", False)
    if type(continued_field) is not bool:
        raise FinalizeError("boot-torn rollback continuation flag is malformed")
    continued_from_normal = continued_field
    claim_owner = "normal-remapper-rollback" if continued_from_normal else experiment_id
    for key, expected in {
        "schema": "sdm855-a90-v024-boot-prefix-physical-claim-v1",
        "claim_key_sha256": effect_key_sha256,
        "claim_identity": effect_identity,
        "claimed_by_experiment_id": claim_owner,
        "effect_replayed": False,
        "claim_status": "COMPLETE",
    }.items():
        _require(claim, key, expected, "torn rollback physical effect claim")
    provenance = claim.get("provenance")
    if not isinstance(provenance, Mapping):
        raise FinalizeError("torn rollback physical claim provenance is not exact")
    if continued_from_normal:
        expected_provenance = {
            "owner_kind": "normal-remapper",
            "profile": "rollback",
            "predecessor_sha256": current_pre_hash,
            "predecessor_size": BOOT_PREFIX_SIZE,
            "image_sha256": ROLLBACK_SHA256,
            "image_size": BOOT_PREFIX_SIZE,
            "journal_path": str(source_path),
        }
    else:
        expected_provenance = {
            "owner_kind": "torn-rollback-recovery",
            "terminal": expected_claim_terminal,
        }
    if any(provenance.get(key) != expected for key, expected in expected_provenance.items()):
        raise FinalizeError("torn rollback physical claim provenance is not exact")
    _utc(claim.get("created_utc"), "torn rollback physical effect claim")
    public_physical = public.get("physical_effect_claim")
    if not isinstance(public_physical, Mapping):
        raise FinalizeError("torn rollback public physical effect claim is missing")
    for key, expected in {
        "attempted": True,
        "claimed": True,
        "key_sha256": effect_key_sha256,
        "claim_sha256": claim_hash,
        "claim_size": claim_size,
    }.items():
        _require(public_physical, key, expected, "torn rollback public physical effect claim")
    source_consumption = public.get("source_consumption")
    if not isinstance(source_consumption, Mapping):
        raise FinalizeError("boot-torn rollback source consumption is missing")
    for key, expected in {
        "claimed": True,
        "attempted": True,
        "source_journal_sha256": source_hash,
        "source_journal_size": source_size,
        "source_profile": "rollback",
    }.items():
        _require(source_consumption, key, expected, "boot-torn rollback source consumption")
    claim_hash = source_consumption.get("claim_sha256")
    claim_size = source_consumption.get("claim_size")
    if not isinstance(claim_hash, str) or SHA256_RE.fullmatch(claim_hash) is None or type(claim_size) is not int or claim_size <= 0 or claim_size > MAX_RECEIPT_BYTES:
        raise FinalizeError("boot-torn rollback source claim hash/size is malformed")
    semantic_sha256 = source_contract["semantic_sha256"]
    semantic_identity = source_contract["semantic_identity"]
    if source_consumption.get("key_sha256") != semantic_sha256:
        raise FinalizeError("boot-torn rollback source-consumption semantic key differs")
    if value.get("source_consumption_claimed") is not True or value.get("source_consumption_claim_attempted") is not True or value.get("source_consumption_claim_sha256") != claim_hash or value.get("source_consumption_claim_size") != claim_size:
        raise FinalizeError("boot-torn rollback private source-consumption binding differs")
    expected_claim_terminal = (
        "terminal_zero_write_close" if write_count == 0 else "before_recovery_effect_marker"
    )
    _require(
        value,
        "source_consumption_claim_terminal",
        expected_claim_terminal,
        "boot-torn rollback source-consumption terminal",
    )
    _require(
        value,
        "source_consumption_claim_phase",
        "before_staging_cleanup",
        "boot-torn rollback source-consumption phase",
    )
    claim_path_value = value.get("source_consumption_claim_path")
    expected_claim_path = root / PRIVATE_ROOT_NAME / f"verification-024-remapper-source-consumed-{semantic_sha256}.claim.json"
    if not isinstance(claim_path_value, str) or Path(claim_path_value).resolve(strict=False) != expected_claim_path.resolve(strict=False):
        raise FinalizeError("boot-torn rollback source-consumption claim path is not hash-bound")
    claim_path = _private_path(
        expected_claim_path, root, "torn rollback source-consumption claim"
    )
    claim, claim_bytes, _ = _json(
        claim_path,
        root=root / PRIVATE_ROOT_NAME,
        label="torn rollback source-consumption claim",
    )
    if (
        hashlib.sha256(claim_bytes).hexdigest() != claim_hash
        or len(claim_bytes) != claim_size
    ):
        raise FinalizeError("boot-torn rollback source-consumption claim hash/size differs")
    for key, expected in {
        "schema": "sdm855-a90-remapper-source-consumption-claim-v1",
        "source_journal_path": str(source_path),
        "source_journal_sha256": source_hash,
        "source_semantic_sha256": semantic_sha256,
        "key_sha256": semantic_sha256,
        "source_semantic_identity": semantic_identity,
        "source_profile": "rollback",
        "source_journal_size": source_size,
        "consumed_by_experiment_id": experiment_id,
        "terminal": expected_claim_terminal,
        "claim_phase": "before_staging_cleanup",
        "effect_replayed": False,
    }.items():
        _require(claim, key, expected, "boot-torn rollback source-consumption claim")
    source_identity = claim.get("source_journal_identity")
    if not isinstance(source_identity, Mapping):
        raise FinalizeError("boot-torn rollback source-consumption identity is missing")
    source_stat = source_path.stat()
    expected_source_identity = {
        "st_dev": source_stat.st_dev,
        "st_ino": source_stat.st_ino,
        "st_mode": source_stat.st_mode,
        "st_size": source_stat.st_size,
        "st_mtime_ns": source_stat.st_mtime_ns,
        "st_ctime_ns": source_stat.st_ctime_ns,
        "sha256": source_hash,
    }
    for key, expected in expected_source_identity.items():
        _require(source_identity, key, expected, "boot-torn rollback source-consumption identity")
    created = claim.get("created_utc")
    _utc(created, "boot-torn rollback source-consumption claim")
    for key, expected in {
        "status": status,
        "target_verified": True,
        "target_evaluation": "VERIFIED",
        "source_flash_journal_sha256": source_hash,
        "source_flash_journal_size": source_size,
        "rollback_sha256": ROLLBACK_SHA256,
        "rollback_size": BOOT_PREFIX_SIZE,
        "cleanup_proved": True,
    }.items():
        _require(public, key, expected, "torn rollback public manifest")
    public_target = public.get("target")
    if not isinstance(public_target, Mapping):
        raise FinalizeError("torn rollback public target object is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "device": TARGET_DEVICE,
        "twrp_version": "3.7.0_12-0",
        "serial_sha256": TARGET_SERIAL_SHA256,
        "status": "VERIFIED",
    }.items():
        _require(public_target, key, expected, "torn rollback public target")
    expected_target = public.get("expected_target")
    if not isinstance(expected_target, Mapping):
        raise FinalizeError("torn rollback expected target object is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "device": TARGET_DEVICE,
        "twrp_version": "3.7.0_12-0",
        "serial_sha256": TARGET_SERIAL_SHA256,
        "boot_alias": "/dev/block/by-name/boot",
        "boot_node": "/dev/block/sda24",
    }.items():
        _require(expected_target, key, expected, "torn rollback expected target")
    effect = public.get("effect")
    if not isinstance(effect, Mapping):
        raise FinalizeError("torn rollback public effect object is missing")
    for key, expected in {
        "command": "fixed boot-prefix rollback dd",
        "transport": ROLLBACK_ADB,
        "write_count": write_count,
        "effect_replayed": False,
        "partition": "/dev/block/sda24",
    }.items():
        _require(effect, key, expected, "torn rollback public effect")
    _require(public, "partition_writes", write_count, "torn rollback public manifest")
    completed = _utc(value.get("completed_utc"), "boot-torn rollback")
    public_completed = _utc(public.get("completed_utc"), "boot-torn rollback public")
    publication_delay = public_completed - completed
    if publication_delay < dt.timedelta(0) or publication_delay > MAX_PUBLICATION_DELAY:
        raise FinalizeError("torn rollback public publication delay is not bounded")
    return {"kind": "rollback_flash", "experiment_id": experiment_id, "path": str(checked), **_receipt_hash(data), "completed_utc": value["completed_utc"], "rescue_terminal": True, "source_journal_sha256": source_hash, "source_journal_size": source_size, "predecessor_sha256": READ_SHA256}


def validate_system_boot(path: Path, root: Path) -> dict[str, object]:
    value, data, checked = _load_public_or_private(
        path, root / PRIVATE_ROOT_NAME, "rollback system boot"
    )
    expected_path = (root / PRIVATE_ROOT_NAME / ROLLBACK_SYSTEM_JOURNAL_NAME).resolve(
        strict=False
    )
    if checked != expected_path:
        raise FinalizeError("rollback system boot path is not the fixed V024 producer")
    # The finalizer is fed the private journal path.  A public manifest at that
    # path, or the retired combined sync/effect command, is never a compatible
    # receipt.
    if value.get("schema") != "sdm855-a90-twrp-system-boot-once-journal-v1":
        raise FinalizeError("rollback system boot private journal schema is not exact")
    experiment_id = _experiment_id(value, "rollback system boot")
    if experiment_id != ROLLBACK_SYSTEM_EXPERIMENT_ID:
        raise FinalizeError("rollback system boot experiment ID is not the fixed V024 producer")
    completed = _utc(value.get("completed_utc"), "rollback system boot")
    for key, expected in {
        "target_verified": True,
        "phase": "rollback",
        "target_model": TARGET_MODEL,
        "target_device": TARGET_DEVICE,
        "twrp_version": "3.7.0_12-0",
        "effect_dispatched": True,
        "effect_replayed": False,
        "effect_dispatch_count": 1,
        "dispatch_count": 1,
        "write_count": 1,
        "preparation_write_count": 1,
        "preparation_read_count": 1,
        "preparation_verified": True,
        "preparation_command": "twrp set tw_reboot_arg system",
        "preparation_read_command": "twrp get tw_reboot_arg",
        "sync_command": "sync",
        "sync_write_count": 1,
        "sync_verified": True,
        "effect_command": "twrp set tw_gui_done 1",
        "effect_argv": ["twrp set tw_gui_done 1"],
        "reboot_dispatched": True,
        "automatic_retries": False,
        "partition_writes": False,
    }.items():
        _require(value, key, expected, "rollback system boot")

    def system_target(target: object, label: str, *, require_reboot_arg: bool) -> Mapping[str, object]:
        if not isinstance(target, Mapping):
            raise FinalizeError(f"{label} target is missing")
        for key, expected in {
            "state": "recovery",
            "model": TARGET_MODEL,
            "device": TARGET_DEVICE,
            "twrp_version": "3.7.0_12-0",
            "serial_sha256": TARGET_SERIAL_SHA256,
            "tw_gui_done": "0",
        }.items():
            _require(target, key, expected, label)
        boot_id = _validate_private_boot_id_receipt(target, label)
        if require_reboot_arg:
            _require(target, "tw_reboot_arg", "system", label)
        return target

    expected_target = value.get("expected_target")
    if not isinstance(expected_target, Mapping):
        raise FinalizeError("rollback system boot expected target is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "device": TARGET_DEVICE,
        "twrp_version": "3.7.0_12-0",
        "serial_sha256": TARGET_SERIAL_SHA256,
    }.items():
        _require(expected_target, key, expected, "rollback system boot expected target")
    initial_target = system_target(
        value.get("target"), "rollback system boot target", require_reboot_arg=False
    )
    recovery_boot_id = initial_target["boot_id"]

    preparation = value.get("preparation")
    if not isinstance(preparation, Mapping):
        raise FinalizeError("rollback system boot preparation is missing")
    for key, expected in {
        "command": "twrp set tw_reboot_arg system",
        "read_command": "twrp get tw_reboot_arg",
        "expected_value": "system",
        "write_count": 1,
        "read_count": 1,
        "read_attempt_count": 1,
        "dispatched": True,
        "verified": True,
        "replayed": False,
    }.items():
        _require(preparation, key, expected, "rollback system boot preparation")
    sync = preparation.get("sync")
    if not isinstance(sync, Mapping):
        raise FinalizeError("rollback system boot sync preparation is missing")
    for key, expected in {
        "command": "sync",
        "status": "SYNC_PREPARATION_VERIFIED",
        "write_count": 1,
        "verified": True,
        "dispatched": True,
    }.items():
        _require(sync, key, expected, "rollback system boot sync preparation")

    def receipt(value: object, label: str) -> Mapping[str, object]:
        if not isinstance(value, Mapping):
            raise FinalizeError(f"{label} receipt is missing")
        encoded = value.get("base64")
        digest = value.get("sha256")
        size = value.get("size")
        if not isinstance(encoded, str) or not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None or type(size) is not int or size < 0 or size > MAX_TRANSPORT_EVIDENCE_BYTES:
            raise FinalizeError(f"{label} receipt is malformed")
        try:
            raw = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeDecodeError, ValueError) as exc:
            raise FinalizeError(f"{label} receipt base64 is malformed") from exc
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise FinalizeError(f"{label} receipt hash/size is not exact")
        return value

    sync_receipt = receipt(sync.get("receipt"), "rollback system boot sync")
    if sync.get("receipt_sha256") != sync_receipt.get("sha256"):
        raise FinalizeError("rollback system boot sync receipt binding differs")

    write_receipt = receipt(
        preparation.get("write_receipt"), "rollback system boot preparation write"
    )
    read_receipt = receipt(
        preparation.get("read_receipt"), "rollback system boot preparation read"
    )
    if (
        preparation.get("write_sha256") != write_receipt.get("sha256")
        or preparation.get("read_sha256") != read_receipt.get("sha256")
        or preparation.get("readback") != "system"
    ):
        raise FinalizeError("rollback system boot preparation receipts are not hash-bound")

    for key, require_arg in (
        ("revalidation_before_preparation", False),
        ("revalidation_after_preparation_marker", False),
        ("revalidation_before_sync", True),
        ("revalidation_before_effect", True),
        ("revalidation_after_effect_marker", True),
    ):
        item = value.get(key)
        if not isinstance(item, Mapping):
            raise FinalizeError(f"rollback system boot {key} is missing")
        _require(item, "verified", True, f"rollback system boot {key}")
        _require(item, "target_verified", True, f"rollback system boot {key}")
        _require(item, "require_reboot_arg", require_arg, f"rollback system boot {key}")
        rebound = system_target(item.get("target"), f"rollback system boot {key}", require_reboot_arg=require_arg)
        if rebound.get("boot_id") != recovery_boot_id:
            raise FinalizeError(
                f"rollback system boot {key} Recovery boot_id differs from initial target"
            )
        if require_arg:
            _require(item, "tw_reboot_arg", "system", f"rollback system boot {key}")
            if rebound.get("tw_reboot_arg") != "system":
                raise FinalizeError(f"rollback system boot {key} reboot argument is not exact")

    effect = value.get("effect")
    if not isinstance(effect, Mapping):
        raise FinalizeError("rollback system boot effect is missing")
    for key, expected in {
        "command": "twrp set tw_gui_done 1",
        "argv": ["twrp set tw_gui_done 1"],
        "dispatch_count": 1,
        "dispatched": True,
        "replayed": False,
        "status": "SYSTEM_BOOT_DISCONNECT_OBSERVED",
        "returned": True,
    }.items():
        _require(effect, key, expected, "rollback system boot effect")
    effect_receipt = receipt(effect.get("receipt"), "rollback system boot effect")
    if effect.get("receipt_sha256") != effect_receipt.get("sha256"):
        raise FinalizeError("rollback system boot effect receipt binding differs")

    physical = value.get("physical_effect_claim")
    if not isinstance(physical, Mapping):
        raise FinalizeError("rollback system boot physical effect claim is missing")
    for key, expected in {"attempted": True, "claimed": True}.items():
        _require(physical, key, expected, "rollback system boot physical effect claim")
    boot_id = physical.get("boot_id")
    if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
        raise FinalizeError("rollback system boot physical claim boot_id is malformed")
    if boot_id != recovery_boot_id:
        raise FinalizeError("rollback system boot physical claim boot_id differs from target")
    physical_boot_id_sha256 = physical.get("boot_id_sha256")
    expected_physical_boot_id_sha256 = hashlib.sha256(boot_id.encode("ascii")).hexdigest()
    # Current truthful producer journals retain the private UUID itself and
    # derive the public hash in ``_public_manifest``.  Bind an emitted
    # private hash when present (newer producer revisions include it), while
    # still accepting that exact producer shape; the public hash below is
    # mandatory and independently checked.
    if physical_boot_id_sha256 is not None and physical_boot_id_sha256 != expected_physical_boot_id_sha256:
        raise FinalizeError("rollback system boot private physical claim boot_id_sha256 differs")
    identity = {
        "schema": "sdm855-a90-twrp-system-effect-claim-v1",
        "current_recovery_boot_id": boot_id,
        "transition": "twrp-system-boot",
        "preparation": "twrp set tw_reboot_arg system",
        "effect": "twrp set tw_gui_done 1",
    }
    key_sha256 = hashlib.sha256(_runtime_json_bytes(identity)).hexdigest()
    if physical.get("key_sha256") != key_sha256:
        raise FinalizeError("rollback system boot physical claim key is not exact")
    claim_path = root / PRIVATE_ROOT_NAME / f"verification-024-twrp-system-effect-{key_sha256}.claim.json"
    if physical.get("claim_path") != str(claim_path.resolve(strict=False)):
        raise FinalizeError("rollback system boot physical claim path is not fixed")
    claim, claim_bytes, _ = _json(claim_path, root=root / PRIVATE_ROOT_NAME, label="rollback system boot physical claim")
    for key, expected in {
        "schema": "sdm855-a90-twrp-system-effect-claim-v1",
        "effect_key_sha256": key_sha256,
        "effect_identity": identity,
        "claimed_by_experiment_id": ROLLBACK_SYSTEM_EXPERIMENT_ID,
        "effect_replayed": False,
    }.items():
        _require(claim, key, expected, "rollback system boot physical claim")
    _utc(claim.get("created_utc"), "rollback system boot physical claim")
    if physical.get("claim_sha256") != hashlib.sha256(claim_bytes).hexdigest() or physical.get("claim_size") != len(claim_bytes):
        raise FinalizeError("rollback system boot physical claim hash/size differs")

    observation = value.get("observation")
    if not isinstance(observation, Mapping) or observation.get("disconnect_observed") is not True:
        raise FinalizeError("rollback system boot observation is not exact")

    public_path = _manifest_path(
        root / MANIFEST_ROOT_NAME / f"{experiment_id}.manifest.json",
        root,
        "rollback system boot public",
    )
    public, _, _ = _json(
        public_path,
        root=root / MANIFEST_ROOT_NAME,
        label="rollback system boot public",
    )
    if public.get("schema") != "sdm855-a90-twrp-system-boot-once-public-v1":
        raise FinalizeError("rollback system boot public schema is not exact")
    if set(public) != _SYSTEM_PUBLIC_TOP_KEYS:
        raise FinalizeError("rollback system boot public top-level fields are not exact")
    for section, expected_keys in _SYSTEM_PUBLIC_NESTED_KEYS.items():
        section_value = public.get(section)
        if not isinstance(section_value, Mapping) or set(section_value) != expected_keys:
            raise FinalizeError(
                f"rollback system boot public {section} fields are not exact"
            )
    _reject_public_raw_boot_ids(public, "rollback system boot public")
    for key, expected in {
        "experiment_id": experiment_id,
        "phase": "rollback",
        "status": "SYSTEM_BOOT_DISCONNECT_OBSERVED",
        "classification": "SYSTEM_BOOT_DISCONNECT_OBSERVED",
        "target_verified": True,
        "target_evaluation": "VERIFIED",
        "target_model": TARGET_MODEL,
        "target_device": TARGET_DEVICE,
        "target_serial_sha256": TARGET_SERIAL_SHA256,
        "twrp_version": "3.7.0_12-0",
        "effect_replayed": False,
        "dispatch_count": 1,
        "effect_dispatched_count": 1,
        "partition_writes": False,
        "partition_write": False,
        "preparation_verified": True,
        "raw_serial_omitted": True,
        "raw_commands_omitted": True,
        "raw_receipts_omitted": True,
        "other_adb_endpoints_untouched": True,
        "journal_sha256": hashlib.sha256(data).hexdigest(),
        "journal_size": len(data),
    }.items():
        _require(public, key, expected, "rollback system boot public")
    started = _utc(value.get("started_utc"), "rollback system boot")
    if _utc(public.get("started_utc"), "rollback system boot public") != started:
        raise FinalizeError("rollback system boot start times differ")
    if _utc(public.get("completed_utc"), "rollback system boot public") != completed:
        raise FinalizeError("rollback system boot completion times differ")
    public_target = public.get("target")
    if not isinstance(public_target, Mapping):
        raise FinalizeError("rollback system boot public target is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "device": TARGET_DEVICE,
        "twrp_version": "3.7.0_12-0",
        "serial_sha256": TARGET_SERIAL_SHA256,
        "state": "recovery",
        "status": "VERIFIED",
        "boot_id_sha256": hashlib.sha256(recovery_boot_id.encode("ascii")).hexdigest(),
    }.items():
        _require(public_target, key, expected, "rollback system boot public target")
    public_expected_target = public.get("expected_target")
    if not isinstance(public_expected_target, Mapping):
        raise FinalizeError("rollback system boot public expected target is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "device": TARGET_DEVICE,
        "twrp_version": "3.7.0_12-0",
        "serial_sha256": TARGET_SERIAL_SHA256,
        "state": "recovery",
    }.items():
        _require(
            public_expected_target,
            key,
            expected,
            "rollback system boot public expected target",
        )
    public_preflight = public.get("preflight")
    if not isinstance(public_preflight, Mapping):
        raise FinalizeError("rollback system boot public preflight is missing")
    initial_help = initial_target.get("twrp_help_receipt")
    expected_help_hash = (
        initial_help.get("sha256")
        if isinstance(initial_help, Mapping)
        else None
    )
    for key, expected in {
        "target_verified": True,
        "tw_gui_done": "0",
        "twrp_help_sha256": expected_help_hash,
    }.items():
        _require(public_preflight, key, expected, "rollback system boot public preflight")
    public_preparation = public.get("preparation")
    if not isinstance(public_preparation, Mapping):
        raise FinalizeError("rollback system boot public preparation is missing")
    for key, expected in {
        "command": "twrp set tw_reboot_arg system",
        "read_command": "twrp get tw_reboot_arg",
        "expected_value": "system",
        "write_count": 1,
        "read_count": 1,
        "verified": True,
        "sync_command": "sync",
        "sync_write_count": 1,
        "sync_verified": True,
        "sync_receipt_sha256": sync_receipt.get("sha256"),
    }.items():
        _require(public_preparation, key, expected, "rollback system boot public preparation")
    public_effect = public.get("effect")
    if not isinstance(public_effect, Mapping):
        raise FinalizeError("rollback system boot public effect is missing")
    for key, expected in {
        "command": "twrp set tw_gui_done 1",
        "dispatch_count": 1,
        "write_count": 1,
        "effect_dispatched_count": 1,
        "effect_replayed": False,
    }.items():
        _require(public_effect, key, expected, "rollback system boot public effect")
    public_claim = public.get("physical_effect_claim")
    if not isinstance(public_claim, Mapping):
        raise FinalizeError("rollback system boot public physical claim is missing")
    for key, expected in {
        "claimed": True,
        "attempted": True,
        "key_sha256": key_sha256,
        "claim_sha256": physical.get("claim_sha256"),
        "claim_size": physical.get("claim_size"),
        "boot_id_sha256": hashlib.sha256(boot_id.encode("ascii")).hexdigest(),
    }.items():
        _require(public_claim, key, expected, "rollback system boot public physical claim")
    public_observation = public.get("observation")
    if not isinstance(public_observation, Mapping):
        raise FinalizeError("rollback system boot public observation is not exact")
    for key, expected in {
        "method": "adb devices endpoint absence only",
        "timeout_sec": 20.0,
        "disconnect_observed": True,
    }.items():
        _require(public_observation, key, expected, "rollback system boot public observation")
    public_claims = public.get("claims")
    expected_claims = {
        "PROVED": [
            "The exact pinned Recovery target was selected before the one-shot transaction."
        ],
        "NO_REPLAY": [
            "The System boot effect has a durable dispatch count and is never retried."
        ],
    }
    if public_claims != expected_claims:
        raise FinalizeError("rollback system boot public claims are not exact")
    return {
        "kind": "rollback_system_boot",
        "experiment_id": experiment_id,
        "path": str(checked),
        **_receipt_hash(data),
        "completed_utc": value["completed_utc"],
    }


def _param_stable_projection(stable_hash: str) -> dict[str, object]:
    """Build the fixed V024 stable-byte projection from a raw-image hash."""

    return {
        "stable_sha256": stable_hash,
        "stable_range": {
            "start": PARAM_STABLE_OFFSET,
            "end": PARAM_STABLE_END,
            "size": PARAM_STABLE_SIZE,
            "sha256": stable_hash,
        },
        "stable_mask": {
            "excluded_ranges": [[0, 1]],
            "stable_ranges": [[PARAM_STABLE_OFFSET, PARAM_STABLE_END]],
            "stable_size": PARAM_STABLE_SIZE,
        },
    }


def _param_stable_sha256(raw_bytes: bytes) -> str:
    """Recompute the V024 stable identity from the complete raw image.

    The caller cannot select a range or mask.  Length is checked by the
    caller before this helper is used, and the fixed constants are deliberately
    local to this finalizer rather than copied from any receipt.
    """

    if type(raw_bytes) is not bytes or len(raw_bytes) != PARAM_CAPTURE_SIZE:
        raise FinalizeError("param stable hash requires the complete 10MiB raw image")
    return hashlib.sha256(raw_bytes[PARAM_STABLE_OFFSET:PARAM_STABLE_END]).hexdigest()


def _param_exact_value(actual: object, expected: object) -> bool:
    """Compare JSON projection values with strict recursive types."""

    if type(actual) is not type(expected):
        return False
    if isinstance(expected, Mapping):
        if set(actual) != set(expected):  # type: ignore[arg-type]
            return False
        return all(
            _param_exact_value(actual[key], expected[key])  # type: ignore[index]
            for key in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(  # type: ignore[arg-type]
            _param_exact_value(item, wanted)
            for item, wanted in zip(actual, expected)  # type: ignore[arg-type]
        )
    return actual == expected


def _require_param_stable_projection(
    obj: object,
    *,
    stable_hash: str,
    raw_hash: str,
    volatile_byte0: int,
    label: str,
) -> Mapping[str, object]:
    """Require one producer-shaped stable/volatile projection exactly."""

    if not isinstance(obj, Mapping):
        raise FinalizeError(f"{label} stable projection is missing")
    projection = _param_stable_projection(stable_hash)
    for key in ("stable_sha256", "stable_range", "stable_mask"):
        actual = obj.get(key)
        if not _param_exact_value(actual, projection[key]):
            raise FinalizeError(f"{label} field {key!r} is not exact")
    for key in ("volatile_byte0", "observed_boot_cycle_volatile_byte0"):
        actual = obj.get(key)
        if type(actual) is not int or not 0 <= actual <= 255:
            raise FinalizeError(f"{label} {key} is not an exact byte")
        if actual != volatile_byte0:
            raise FinalizeError(f"{label} {key} is not bound to raw byte 0")
    # Some downstream producer revisions expose this alias at the projection
    # level.  It is not optional once present: a forged alias must fail closed.
    for alias in ("sha256", "full_sha256"):
        if alias in obj:
            _require_hash(obj.get(alias), raw_hash, f"{label} {alias}")
    return obj


def _require_param_capture_hashes(
    obj: object,
    *,
    stable_hash: str,
    raw_hash: str,
    volatile_byte0: int,
    label: str,
    require_triple_hash_match: bool = True,
) -> Mapping[str, object]:
    """Require one public/private nested capture projection bound to raw."""

    capture = _require_param_stable_projection(
        obj,
        stable_hash=stable_hash,
        raw_hash=raw_hash,
        volatile_byte0=volatile_byte0,
        label=label,
    )
    for key in ("sha256", "full_sha256", "device_sha256_before", "device_sha256_after"):
        _require_hash(capture.get(key), raw_hash, f"{label} {key}")
    _require_size(capture.get("size"), PARAM_CAPTURE_SIZE, label)
    if require_triple_hash_match:
        _require(capture, "triple_hash_match", True, label)
    return capture


def validate_param_capture(path: Path, root: Path) -> dict[str, object]:
    value, data, checked = _load_evidence_json(path, root, "final LOW param capture")
    # The final gate consumes the public artifact emitted by
    # a90_param_capture.py.  A private metadata file or a historical summary
    # is not a substitute for this producer's complete public geometry and
    # hash contract.
    _require(value, "schema", "sdm855-a90-param-capture-public-v1", "param capture")
    experiment_id = _experiment_id(value, "param capture")
    if checked != (root / MANIFEST_ROOT_NAME / PARAM_CAPTURE_MANIFEST_NAME).resolve(strict=False):
        raise FinalizeError("param capture path is not the fixed V024 producer")
    if experiment_id != PARAM_CAPTURE_EXPERIMENT_ID:
        raise FinalizeError("param capture experiment ID is not the fixed V024 producer")
    completed_value = value.get("completed_utc")
    started_value = value.get("started_utc")
    completed = _utc(completed_value, "param capture")
    _utc(started_value, "param capture started")
    if _utc(started_value, "param capture started") > completed:
        raise FinalizeError("param capture started after completion")
    for key, expected in {
        "stophud_accepted": True,
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": PARAM_RUNTIME,
        "kernel": TARGET_KERNEL,
        "bootloader": TARGET_BOOTLOADER,
        "download_mode": "1",
        "classification": "PARAM_CAPTURED_DEBUG_ONLY_PRECONDITIONS_MET",
        "partition_writes": False,
        "raw_artifact_git_ignored": True,
    }.items():
        _require(value, key, expected, "param capture")
    retries = value.get("stophud_busy_retries")
    if type(retries) is not int or retries < 0 or retries > 8:
        raise FinalizeError("param capture stophud retry count is not bounded")

    partition = value.get("partition")
    if not isinstance(partition, Mapping):
        raise FinalizeError("param capture partition geometry is missing")
    for key, expected in {
        "partname": PARAM_PARTNAME,
        "devname": PARAM_DEVNAME,
        "major": PARAM_MAJOR,
        "minor": PARAM_MINOR,
        "sectors": PARAM_PARTITION_SECTORS,
        "byte_size": PARAM_PARTITION_BYTES,
        "start_sector": PARAM_START_SECTOR,
        "read_only": 0,
        "logical_block_size": PARAM_LOGICAL_BLOCK_SIZE,
    }.items():
        _require(partition, key, expected, "param capture partition")

    private_dir = _private_path(
        root / PRIVATE_ROOT_NAME / experiment_id, root, "param private directory"
    )
    raw_name = "param--sda10.bin"
    metadata_name = "capture-metadata.json"
    journal_name = "capture-journal.json"
    raw_path = _private_path(private_dir / raw_name, root, "param raw")
    metadata_path = _private_path(private_dir / metadata_name, root, "param metadata")
    journal_path = _private_path(private_dir / journal_name, root, "param journal")
    raw_bytes = _stable_bytes(
        raw_path,
        root=root / PRIVATE_ROOT_NAME,
        label="param raw",
        max_bytes=PARAM_CAPTURE_SIZE + 1,
    )
    if len(raw_bytes) != PARAM_CAPTURE_SIZE:
        raise FinalizeError("param raw artifact is not exact 10MiB")
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    stable_hash = _param_stable_sha256(raw_bytes)
    volatile_byte0 = raw_bytes[0]

    # The public top-level projection and its nested capture are both
    # producer outputs.  Neither is trusted to select the stable range or
    # mask; the expected values above are compared to the recomputation.
    _require_param_stable_projection(
        value,
        stable_hash=stable_hash,
        raw_hash=raw_hash,
        volatile_byte0=volatile_byte0,
        label="param capture",
    )
    capture = _require_param_capture_hashes(
        value.get("capture"),
        stable_hash=stable_hash,
        raw_hash=raw_hash,
        volatile_byte0=volatile_byte0,
        label="param capture",
    )
    if stable_hash != PARAM_STABLE_LOW_SHA256:
        raise FinalizeError("param raw artifact is not exact V024 stable LOW hash")
    if raw_hash != capture.get("sha256") or len(raw_bytes) != capture.get("size"):
        raise FinalizeError("param public/raw hash binding is not exact")

    expected_decoded = {
        "debuglevel": {
            "partition_offset": "0x900000",
            "record_offset": "0x000",
            "value": PARAM_LOW_DEBUG_VALUE,
            "label": "LOW",
        },
        "force_upload_flag": {
            "partition_offset": "0x9003f4",
            "record_offset": "0x3f4",
            "value": PARAM_FORCE_UPLOAD_VALUE,
            "label": "NOT_ENABLED_VALUE_5",
        },
        "FMM_lock": {
            "partition_offset": "0x9003fc",
            "record_offset": "0x3fc",
            "value": PARAM_FMM_LOCK_VALUE,
            "label": "NOT_LOCK_MAGIC",
        },
        "dump_sink": {
            "partition_offset": "0x900400",
            "record_offset": "0x400",
            "value": PARAM_DUMP_SINK_VALUE,
            "label": "USB_DEFAULT",
        },
    }
    if value.get("decoded_gate_fields") != expected_decoded:
        raise FinalizeError("param capture decoded LOW fields are not exact")
    # Bind the human-readable decoder projection to the retained bytes.  A
    # copied summary must not survive a mutation at any of the four exact
    # source-backed offsets.
    for offset, expected, label in (
        (PARAM_DEBUG_OFFSET, b"DLOW", "debuglevel"),
        (PARAM_FORCE_UPLOAD_OFFSET, b"\x00\x00\x00\x00", "force_upload"),
        (PARAM_FMM_LOCK_OFFSET, b"\x00\x00\x00\x00", "FMM_lock"),
        (PARAM_DUMP_SINK_OFFSET, b"\x00\x00\x00\x00", "dump_sink"),
    ):
        if raw_bytes[offset : offset + 4] != expected:
            raise FinalizeError(f"param raw {label} bytes are not exact")
    relevant = value.get("cmdline_relevant")
    if not isinstance(relevant, Mapping):
        raise FinalizeError("param capture complete cmdline binding is missing")
    if dict(relevant) != {
        "androidboot.em.model": TARGET_MODEL,
        "androidboot.bootloader": TARGET_BOOTLOADER,
        "androidboot.debug_level": "0x4f4c",
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
        "androidboot.upload_offset": PARAM_CMDLINE_UPLOAD_OFFSET,
    }:
        raise FinalizeError("param capture cmdline binding is not exact final LOW")

    metadata, metadata_bytes, _ = _json(
        metadata_path, root=root / PRIVATE_ROOT_NAME, label="param metadata"
    )
    _require(metadata, "schema", "sdm855-a90-param-capture-private-v1", "param metadata")
    _require(metadata, "experiment_id", experiment_id, "param metadata")
    _require(metadata, "started_utc", started_value, "param metadata")
    _require(metadata, "completed_utc", completed_value, "param metadata")
    _require(metadata, "target_model", TARGET_MODEL, "param metadata")
    _require(metadata, "soc", TARGET_SOC, "param metadata")
    _require(metadata, "download_mode", "1", "param metadata")
    _require(metadata, "partition_writes", False, "param metadata")
    _require(metadata, "arbitration_journal", journal_name, "param metadata")
    _require_param_stable_projection(
        metadata,
        stable_hash=stable_hash,
        raw_hash=raw_hash,
        volatile_byte0=volatile_byte0,
        label="param metadata",
    )
    runtime_payload = metadata.get("runtime_payload")
    if not isinstance(runtime_payload, str):
        raise FinalizeError("param metadata runtime payload is missing")
    if "\r" in runtime_payload.replace("\r\n", ""):
        raise FinalizeError("param metadata runtime payload contains a bare CR")
    runtime_text = runtime_payload.replace("\r\n", "\n")
    if runtime_text.endswith("\n"):
        runtime_text = runtime_text[:-1]
    runtime_lines = runtime_text.split("\n")
    if any(not line for line in runtime_lines):
        raise FinalizeError("param metadata runtime payload has empty framing")
    expected_runtime_lines = [
        "A90 Linux init 0.9.285 (v2321-usb-clean-identity-rodata)",
        "version: 0.9.285 build=v2321-usb-clean-identity-rodata",
        "kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
    ]
    identity_lines = [
        line
        for line in runtime_lines
        if line.startswith(("A90 Linux init ", "version: ", "kernel: "))
    ]
    if identity_lines != expected_runtime_lines:
        raise FinalizeError("param metadata runtime identity is not exact or ordered")
    for line in runtime_lines:
        if line in expected_runtime_lines or line == "made by device owner":
            continue
        if re.fullmatch(
            r"display: [0-9]+x[0-9]+(?: connector=[0-9]+)?(?: crtc=[0-9]+)?(?: fb=[0-9]+)?",
            line,
        ) is None:
            raise FinalizeError("param metadata runtime metadata line is not exact")
    cmdline = metadata.get("cmdline")
    if not isinstance(cmdline, Mapping):
        raise FinalizeError("param metadata complete cmdline is missing")
    for key, item in cmdline.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise FinalizeError("param metadata cmdline has non-string fields")
        if key in {"skip_initramfs", "rootwait", "ro"}:
            if item != "":
                raise FinalizeError("param metadata known bare flag has a value")
        elif _RUNTIME_CMDLINE_KEY_RE.fullmatch(key) is None or any(
            ord(char) < 0x21 or ord(char) == 0x7F for char in item
        ) or not item:
            raise FinalizeError("param metadata cmdline token is malformed")
    for key, expected in {
        "androidboot.em.model": TARGET_MODEL,
        "androidboot.bootloader": TARGET_BOOTLOADER,
        "androidboot.debug_level": "0x4f4c",
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
        "androidboot.upload_offset": PARAM_CMDLINE_UPLOAD_OFFSET,
    }.items():
        _require(cmdline, key, expected, "param metadata cmdline")
    metadata_partition = metadata.get("partition")
    if not isinstance(metadata_partition, Mapping):
        raise FinalizeError("param metadata partition geometry is missing")
    for key, expected in {
        "partname": PARAM_PARTNAME,
        "devname": PARAM_DEVNAME,
        "major": PARAM_MAJOR,
        "minor": PARAM_MINOR,
        "sectors": PARAM_PARTITION_SECTORS,
        "byte_size": PARAM_PARTITION_BYTES,
        "start_sector": PARAM_START_SECTOR,
        "read_only": 0,
        "logical_block_size": PARAM_LOGICAL_BLOCK_SIZE,
        "node_path": PARAM_NODE_PATH,
    }.items():
        _require(metadata_partition, key, expected, "param metadata partition")
    metadata_capture = metadata.get("capture")
    metadata_capture = _require_param_capture_hashes(
        metadata_capture,
        stable_hash=stable_hash,
        raw_hash=raw_hash,
        volatile_byte0=volatile_byte0,
        label="param metadata capture",
        require_triple_hash_match=False,
    )
    _require(metadata_capture, "private_filename", raw_name, "param metadata capture")
    for key in ("sha256", "full_sha256", "device_sha256_before", "device_sha256_after"):
        if metadata_capture.get(key) != capture.get(key):
            raise FinalizeError(f"param metadata/public {key} binding differs")
    _require(metadata, "decoded_gate_fields", expected_decoded, "param metadata")
    for key in (
        "stable_sha256",
        "stable_range",
        "stable_mask",
        "volatile_byte0",
        "observed_boot_cycle_volatile_byte0",
    ):
        if metadata.get(key) != value.get(key):
            raise FinalizeError(f"param metadata/public {key} binding differs")
    for key in ("stable_sha256", "stable_range", "stable_mask", "volatile_byte0", "observed_boot_cycle_volatile_byte0"):
        if metadata_capture.get(key) != capture.get(key):
            raise FinalizeError(f"param metadata/public capture {key} binding differs")
    a90p1_end = metadata_capture.get("a90p1_end")
    if not isinstance(a90p1_end, Mapping):
        raise FinalizeError("param metadata capture transport terminal is missing")
    for key, expected in {
        "cmd": "cat",
        "errno": "0",
        "flags": "0x0",
        "rc": "0",
        "status": "ok",
    }.items():
        _require(a90p1_end, key, expected, "param metadata capture terminal")
    for key in ("seq", "duration_ms"):
        raw_value = a90p1_end.get(key)
        if not isinstance(raw_value, str) or re.fullmatch(r"[0-9]+", raw_value) is None:
            raise FinalizeError(f"param metadata capture terminal {key} is malformed")

    journal, journal_bytes, _ = _json(
        journal_path, root=root / PRIVATE_ROOT_NAME, label="param journal"
    )
    for key, expected in {
        "schema": "sdm855-a90-param-capture-arbitration-journal-v1",
        "experiment_id": experiment_id,
        "status": "COMPLETE",
        "completed_utc": completed_value,
        "effect_dispatched": False,
        "effect_replayed": False,
        "cleanup_deferred": False,
        "reconcile_required": False,
        "cleanup_error": None,
        "target_verified": True,
        "private_metadata": metadata_name,
        "retained_size": PARAM_CAPTURE_SIZE,
    }.items():
        _require(journal, key, expected, "param journal")
    _require_hash(journal.get("retained_sha256"), raw_hash, "param journal retained_sha256")
    _require_hash(
        journal.get("retained_stable_sha256"),
        stable_hash,
        "param journal retained_stable_sha256",
    )
    retained_volatile = journal.get("retained_volatile_byte0")
    if type(retained_volatile) is not int or not 0 <= retained_volatile <= 255:
        raise FinalizeError("param journal retained_volatile_byte0 is not an exact byte")
    if retained_volatile != volatile_byte0:
        raise FinalizeError("param journal retained_volatile_byte0 is not bound to raw byte 0")
    journal_target = journal.get("target")
    if not isinstance(journal_target, Mapping):
        raise FinalizeError("param journal target binding is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": PARAM_RUNTIME,
        "kernel": TARGET_KERNEL,
    }.items():
        _require(journal_target, key, expected, "param journal target")
    if journal.get("retained_sha256") != capture.get("sha256") or journal.get("retained_size") != capture.get("size"):
        raise FinalizeError("param journal/public hash binding differs")
    if journal.get("retained_stable_sha256") != capture.get("stable_sha256"):
        raise FinalizeError("param journal/public stable hash binding differs")
    if journal.get("retained_volatile_byte0") != capture.get("volatile_byte0"):
        raise FinalizeError("param journal/public volatile byte binding differs")
    return {
        "kind": "param_capture",
        "experiment_id": experiment_id,
        "path": str(checked),
        **_receipt_hash(data),
        "raw_sha256": raw_hash,
        "raw_size": len(raw_bytes),
        "stable_sha256": stable_hash,
        "stable_size": PARAM_STABLE_SIZE,
        "volatile_byte0": volatile_byte0,
        "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
        "metadata_size": len(metadata_bytes),
        "journal_sha256": hashlib.sha256(journal_bytes).hexdigest(),
        "journal_size": len(journal_bytes),
        "completed_utc": completed_value,
    }


_RUNTIME_TEMP_PATHS = [
    "/tmp/a90-native/verification-024-sda24",
    "/tmp/a90-native/verification-024-boot-prefix.bin",
    "/tmp/sdm855_mblab_param_debug_payload",
    "/tmp/sdm855_mblab_param_debug_dd_smoke",
    "/dev/sdm855_mblab_sda10",
]
_RUNTIME_BOOT_NODE = _RUNTIME_TEMP_PATHS[0]
_RUNTIME_BOOT_FILE = _RUNTIME_TEMP_PATHS[1]
_RUNTIME_BOOT_SYSFS_ROOT = "/sys/class/block/sda24"
_RUNTIME_BOOT_UEVENT = _RUNTIME_BOOT_SYSFS_ROOT + "/uevent"
_RUNTIME_BOOT_SIZE = _RUNTIME_BOOT_SYSFS_ROOT + "/size"
_RUNTIME_BOOT_RO = _RUNTIME_BOOT_SYSFS_ROOT + "/ro"
_RUNTIME_BOOT_DIR = "/tmp/a90-native"
_RUNTIME_BOOT_EXPECTED_STAT_BASE = {
    "mode": "0600",
    "uid": "0",
    "gid": "0",
    "size": "0",
}
_RUNTIME_BOOT_BINDING_STAGES = (
    "pre-attestation cleanup",
    "boot_attest_remove_node binding",
    "boot_attest_remove_file binding",
    "attestation mkdir",
    "attestation mknod",
    "attestation capture",
    "post-attestation cleanup",
    "boot_attest_remove_node binding",
    "boot_attest_remove_file binding",
)
_RUNTIME_RECORD_KEYS = {
    "evidence_id",
    "argv",
    "begin",
    "end",
    "payload_base64",
    "payload_sha256",
    "payload_size",
    "transcript_base64",
    "transcript_sha256",
    "transcript_size",
}
_RUNTIME_PUBLIC_RECORD_KEYS = (
    "evidence_id",
    "argv",
    "end",
    "payload_sha256",
    "payload_size",
    "transcript_sha256",
    "transcript_size",
)
_RUNTIME_CMDLINE_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]+\Z")


def _runtime_json_bytes(value: object) -> bytes:
    """Match the shared producer's stable indented JSON serialization."""

    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _runtime_absence_commands(prefix: str, path: str) -> list[tuple[str, tuple[str, ...]]]:
    return [
        (prefix, ("run", "/bin/toybox", "test", "!", "-e", path)),
        (
            prefix + "_not_symlink",
            ("run", "/bin/toybox", "test", "!", "-L", path),
        ),
    ]


def _runtime_expected_commands() -> list[tuple[str, tuple[str, ...] | None]]:
    commands: list[tuple[str, tuple[str, ...] | None]] = [
        ("version", ("version",)),
        ("cmdline", ("cat", "/proc/cmdline")),
        ("soc_id", ("cat", "/sys/devices/soc0/soc_id")),
        ("panic_on_oops", ("cat", "/proc/sys/kernel/panic_on_oops")),
    ]
    commands.extend(
        [
            ("boot_attest_remove_node", ("run", "/bin/toybox", "rm", "-f", _RUNTIME_BOOT_NODE)),
            ("boot_attest_remove_file", ("run", "/bin/toybox", "rm", "-f", _RUNTIME_BOOT_FILE)),
        ]
    )
    commands.extend(_runtime_absence_commands("boot_attest_node_absent", _RUNTIME_BOOT_NODE))
    commands.extend(_runtime_absence_commands("boot_attest_file_absent", _RUNTIME_BOOT_FILE))
    commands.extend(_runtime_absence_commands("boot_attest_pre_node_absent", _RUNTIME_BOOT_NODE))
    commands.extend(_runtime_absence_commands("boot_attest_pre_file_absent", _RUNTIME_BOOT_FILE))
    commands.extend(
        [
            ("boot_sysfs_uevent", ("cat", _RUNTIME_BOOT_UEVENT)),
            ("boot_sysfs_size", ("cat", _RUNTIME_BOOT_SIZE)),
            ("boot_sysfs_ro", ("cat", _RUNTIME_BOOT_RO)),
            ("boot_attest_mkdir", ("run", "/bin/toybox", "mkdir", "-p", _RUNTIME_BOOT_DIR)),
            # The block dev_t is allocated by the running kernel and is bound
            # from this run's uevent frame during validation.
            ("boot_attest_mknod", None),
            ("boot_attest_stat_node", ("stat", _RUNTIME_BOOT_NODE)),
            (
                "boot_attest_capture",
                (
                    "run",
                    "/bin/toybox",
                    "dd",
                    f"if={_RUNTIME_BOOT_NODE}",
                    f"of={_RUNTIME_BOOT_FILE}",
                    "bs=4096",
                    "count=14864",
                    "conv=fsync",
                    "status=none",
                ),
            ),
            ("boot_attest_hash", ("run", "/bin/toybox", "sha256sum", _RUNTIME_BOOT_FILE)),
            ("boot_attest_size", ("run", "/bin/toybox", "wc", "-c", _RUNTIME_BOOT_FILE)),
            ("boot_attest_remove_node", ("run", "/bin/toybox", "rm", "-f", _RUNTIME_BOOT_NODE)),
            ("boot_attest_remove_file", ("run", "/bin/toybox", "rm", "-f", _RUNTIME_BOOT_FILE)),
        ]
    )
    commands.extend(_runtime_absence_commands("boot_attest_node_absent", _RUNTIME_BOOT_NODE))
    commands.extend(_runtime_absence_commands("boot_attest_file_absent", _RUNTIME_BOOT_FILE))
    for index, path in enumerate(_RUNTIME_TEMP_PATHS):
        commands.extend(_runtime_absence_commands(f"v024_temp_{index}", path))
    commands.extend(
        [
            ("selftest", ("selftest", "status")),
            ("battery_capacity", ("cat", "/sys/class/power_supply/battery/capacity")),
        ]
    )
    return commands


_RUNTIME_EXPECTED_COMMANDS = _runtime_expected_commands()


def _runtime_expected_argv(
    evidence_id: str,
    expected_argv: tuple[str, ...] | None,
    record: object,
    label: str,
) -> tuple[str, ...]:
    """Resolve one runtime argv, binding mknod's dev_t to its frame."""

    if evidence_id == "boot_attest_mknod":
        if expected_argv is not None:
            raise FinalizeError(f"{label} dynamic mknod entry has a fixed argv")
        if not isinstance(record, Mapping):
            raise FinalizeError(f"{label} mknod frame is not an object")
        return _validate_dynamic_mknod_argv(record.get("argv"), label)
    if expected_argv is None:
        raise FinalizeError(f"{label} non-mknod entry has no argv")
    return expected_argv


def _runtime_decode_b64(
    value: object, label: str, *, max_bytes: int = MAX_TRANSPORT_EVIDENCE_BYTES
) -> bytes:
    if not isinstance(value, str) or len(value) > max_bytes * 2:
        raise FinalizeError(f"{label} base64 is missing or oversized")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise FinalizeError(f"{label} base64 is malformed") from exc
    if len(decoded) > max_bytes:
        raise FinalizeError(f"{label} evidence is oversized")
    return decoded


def _runtime_frame(
    record: object,
    evidence_id: str,
    argv: tuple[str, ...],
    label: str,
    *,
    expected_rc: str = "0",
    expected_status: str = "ok",
    max_bytes: int = MAX_TRANSPORT_EVIDENCE_BYTES,
) -> tuple[bytes, bytes]:
    if not isinstance(record, Mapping):
        raise FinalizeError(f"{label} frame is not an object")
    if set(record) != _RUNTIME_RECORD_KEYS:
        raise FinalizeError(f"{label} frame fields are incomplete or forged")
    if record.get("evidence_id") != evidence_id or record.get("argv") != list(argv):
        raise FinalizeError(f"{label} evidence ID/argv is not exact")
    begin = record.get("begin")
    end = record.get("end")
    if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
        raise FinalizeError(f"{label} begin/end is missing")
    if set(begin) != _FRAME_BEGIN_KEYS or set(end) != _FRAME_END_KEYS:
        raise FinalizeError(f"{label} begin/end fields are not exact")
    if begin.get("cmd") != argv[0] or end.get("cmd") != argv[0]:
        raise FinalizeError(f"{label} begin/end command is not exact")
    begin_seq = begin.get("seq")
    end_seq = end.get("seq")
    if (
        not isinstance(begin_seq, str)
        or _CANONICAL_DECIMAL_RE.fullmatch(begin_seq) is None
        or end_seq != begin_seq
        or begin.get("argc") != str(len(argv))
        or begin.get("flags") != inline_protocol_flags_for_argv(argv)
        or end.get("rc") != expected_rc
        or not isinstance(end.get("errno"), str)
        or _CANONICAL_DECIMAL_RE.fullmatch(end.get("errno", "")) is None
        or end.get("errno") != inline_protocol_expected_errno(expected_rc)
        or not isinstance(end.get("duration_ms"), str)
        or _CANONICAL_DECIMAL_RE.fullmatch(end.get("duration_ms", "")) is None
        or end.get("flags") != inline_protocol_flags_for_argv(argv)
        or end.get("status") != expected_status
    ):
        raise FinalizeError(f"{label} begin/end sequence or terminal is not exact")
    payload = _runtime_decode_b64(
        record.get("payload_base64"), f"{label} payload", max_bytes=max_bytes
    )
    transcript = _runtime_decode_b64(
        record.get("transcript_base64"), f"{label} transcript", max_bytes=max_bytes
    )
    if (
        type(record.get("payload_size")) is not int
        or record.get("payload_size") != len(payload)
        or not isinstance(record.get("payload_sha256"), str)
        or SHA256_RE.fullmatch(record["payload_sha256"]) is None
        or record["payload_sha256"] != hashlib.sha256(payload).hexdigest()
        or type(record.get("transcript_size")) is not int
        or record.get("transcript_size") != len(transcript)
        or not isinstance(record.get("transcript_sha256"), str)
        or SHA256_RE.fullmatch(record["transcript_sha256"]) is None
        or record["transcript_sha256"] != hashlib.sha256(transcript).hexdigest()
    ):
        raise FinalizeError(f"{label} payload/transcript hash or size is not exact")
    if argv == STOPHUD_ARGV:
        try:
            validate_stophud_evidence_sizes(payload, transcript)
        except BaseException as exc:
            raise FinalizeError(
                f"{label} stophud evidence size is not bounded"
            ) from exc
    if not transcript:
        raise FinalizeError(f"{label} transcript is empty")
    if len(BEGIN_RE.findall(transcript)) != 1 or len(END_RE.findall(transcript)) != 1:
        raise FinalizeError(f"{label} transcript has duplicate or incomplete framing")
    try:
        parsed = parse_last_frame(transcript, argv[0])
    except (TypeError, ValueError) as exc:
        raise FinalizeError(f"{label} transcript framing is not complete") from exc
    if (
        parsed.begin != dict(begin)
        or parsed.end != dict(end)
        or parsed.payload != payload
    ):
        raise FinalizeError(f"{label} transcript does not bind begin/end/payload")
    begin_match = next(BEGIN_RE.finditer(transcript), None)
    end_match = next(END_RE.finditer(transcript), None)
    if begin_match is None or end_match is None or end_match.start() < begin_match.end():
        raise FinalizeError(f"{label} transcript boundaries are not ordered")
    _validate_protocol_tail(transcript, end_match, label)
    if not inline_protocol_terminal_and_tail_valid(
        transcript, begin_match, end_match, argv, end
    ):
        raise FinalizeError(f"{label} terminal/tail is not exact")
    body = transcript[begin_match.end() : end_match.start()]
    terminal_matches = list(
        re.finditer(
            rb"(?:^|\r?\n)\[(?P<kind>done|err|busy)\] [^\r\n]*(?:\r\n|\n|\Z)",
            body,
        )
    )
    expected_kind = "busy" if expected_rc == "-16" and expected_status == "busy" else "done" if expected_rc == "0" and expected_status == "ok" else "err"
    if len(terminal_matches) != 1 or terminal_matches[0].group("kind").decode("ascii") != expected_kind:
        raise FinalizeError(f"{label} transcript terminal marker is not bound to rc/status")
    return payload, transcript


def _runtime_public_record(record: Mapping[str, object]) -> dict[str, object]:
    return {key: record[key] for key in _RUNTIME_PUBLIC_RECORD_KEYS}


def _runtime_binding_equal(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Compare identity-bearing runtime bridge bindings across attestations."""

    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def _runtime_line(payload: bytes, expected: bytes, label: str) -> None:
    if payload not in _payload_line_variants(expected):
        raise FinalizeError(f"{label} payload is not exact")


def _finalizer_cmdline_body(payload: bytes, label: str) -> str:
    """Decode one cmdline using the native ASCII-space delimiter contract."""

    if b"\x00" in payload:
        raise FinalizeError(f"{label} contains NUL")
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise FinalizeError(f"{label} is not ASCII") from exc
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text or text[0].isspace() or text[-1].isspace():
        raise FinalizeError(f"{label} framing is not exact")
    if any(char.isspace() and char != " " for char in text):
        raise FinalizeError(f"{label} contains non-space whitespace")
    return text


def _runtime_cmdline(payload: bytes) -> dict[str, str]:
    text = _finalizer_cmdline_body(payload, "runtime cmdline")
    values: dict[str, str] = {}
    for token in (item for item in text.split(" ") if item):
        if "=" not in token:
            if token not in {"skip_initramfs", "rootwait", "ro"} or token in values:
                raise FinalizeError("runtime cmdline has an unexpected flag")
            values[token] = ""
            continue
        key, value = token.split("=", 1)
        if (
            not key
            or not value
            or key in values
            or _RUNTIME_CMDLINE_KEY_RE.fullmatch(key) is None
            or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
        ):
            raise FinalizeError("runtime cmdline key/value is malformed")
        values[key] = value
    required = {
        "androidboot.em.model": TARGET_MODEL,
        "androidboot.bootloader": TARGET_BOOTLOADER,
        "androidboot.debug_level": "0x4f4c",
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
    }
    for key, expected in required.items():
        if values.get(key) != expected:
            raise FinalizeError("runtime cmdline is not the exact rollback target")
    return values


def _last_cmdline(payload: bytes) -> dict[str, str]:
    """Parse the pre-read MID cmdline with the same closed token grammar."""

    text = _finalizer_cmdline_body(payload, "last-kmsg cmdline")
    values: dict[str, str] = {}
    for token in (item for item in text.split(" ") if item):
        if "=" not in token:
            if token not in {"skip_initramfs", "rootwait", "ro"} or token in values:
                raise FinalizeError("last-kmsg cmdline has an unexpected flag")
            values[token] = ""
            continue
        key, item = token.split("=", 1)
        if (
            not item
            or key in values
            or _RUNTIME_CMDLINE_KEY_RE.fullmatch(key) is None
            or any(ord(char) < 0x21 or ord(char) == 0x7F for char in item)
        ):
            raise FinalizeError("last-kmsg cmdline key/value is malformed")
        values[key] = item
    required = {
        "androidboot.em.model": TARGET_MODEL,
        "androidboot.bootloader": TARGET_BOOTLOADER,
        "androidboot.debug_level": "0x494d",
    }
    for key, expected in required.items():
        if values.get(key) != expected:
            raise FinalizeError("last-kmsg cmdline identity is not exact")
    if values.get("androidboot.force_upload") not in {"0", "0x0"} or values.get("sec_debug.dump_sink") not in {"0", "0x0"}:
        raise FinalizeError("last-kmsg cmdline LOW/MID flags are not exact")
    return values


def _runtime_toybox_success(payload: bytes, label: str) -> None:
    try:
        # Use the same closed parser as inline/source evidence.  In
        # particular, the retained producer permits LF/CRLF and an optional
        # final line ending, but never a bare CR, duplicate marker, or hidden
        # trailing record.
        _semantic_toybox_body(payload, label)
    except BaseException as exc:
        raise FinalizeError(f"{label} toybox framing is not one run/exit-0 record") from exc


def _runtime_toybox_body(payload: bytes, label: str) -> bytes:
    return _semantic_toybox_body(payload, label)


def _runtime_validate_frame_set(
    frames: object,
    expected: list[tuple[str, tuple[str, ...] | None]],
    label: str,
) -> list[bytes]:
    if not isinstance(frames, list) or len(frames) != len(expected):
        raise FinalizeError(f"{label} frame sequence is incomplete or duplicated")
    payloads: list[bytes] = []
    for index, ((evidence_id, expected_argv), frame) in enumerate(zip(expected, frames)):
        argv = _runtime_expected_argv(
            evidence_id, expected_argv, frame, f"{label}[{index}]"
        )
        payload, _ = _runtime_frame(frame, evidence_id, argv, f"{label}[{index}]")
        payloads.append(payload)
    return payloads


def _validate_last_transport_records(
    records: object, label: str
) -> list[bytes]:
    expected = [
        ("version_before", ("version",)),
        ("cmdline_before", ("cat", "/proc/cmdline")),
        ("boot_id_after_source", ("cat", "/proc/sys/kernel/random/boot_id")),
        ("last_kmsg", ("cat", "/proc/last_kmsg")),
        ("selftest_after", ("selftest", "status")),
    ]
    if not isinstance(records, list) or len(records) != len(expected):
        raise FinalizeError(f"{label} frame sequence is incomplete or duplicated")
    payloads: list[bytes] = []
    for index, ((evidence_id, argv), frame) in enumerate(zip(expected, records)):
        payload, _ = _runtime_frame(
            frame,
            evidence_id,
            argv,
            f"{label}[{index}]",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        payloads.append(payload)
    return payloads


def _validate_last_stophud(
    public: Mapping[str, object],
    metadata: Mapping[str, object],
    journal: Mapping[str, object],
) -> None:
    """Validate the last-kmsg stophud attempt summaries and full frames."""

    stophud = metadata.get("stophud")
    frames = metadata.get("stophud_frames")
    attempts = stophud.get("attempts") if isinstance(stophud, Mapping) else None
    if (
        not isinstance(stophud, Mapping)
        or stophud.get("accepted") is not True
        or not isinstance(attempts, list)
        or not isinstance(frames, list)
        or not attempts
        or len(attempts) > STOPHUD_MAX_ATTEMPTS
        or len(attempts) != len(frames)
    ):
        raise FinalizeError("last-kmsg stophud attempts/frames are incomplete")
    busy_retries = 0
    for index, (attempt, frame) in enumerate(zip(attempts, frames), 1):
        if not isinstance(attempt, Mapping):
            raise FinalizeError("last-kmsg stophud attempt is malformed")
        if (
            set(attempt)
            != {
                "attempt",
                "rc",
                "status",
                "evidence_id",
                "payload_size",
                "payload_sha256",
                "transcript_size",
                "transcript_sha256",
            }
            or attempt.get("attempt") != index
            or attempt.get("evidence_id") != f"stophud_{index}"
        ):
            raise FinalizeError("last-kmsg stophud attempt identity is not exact")
        rc = attempt.get("rc")
        status = attempt.get("status")
        if type(rc) is not int or status not in {"busy", "ok"}:
            raise FinalizeError("last-kmsg stophud attempt terminal is malformed")
        expected_rc = -16 if index < len(attempts) else 0
        expected_status = "busy" if index < len(attempts) else "ok"
        if rc != expected_rc or status != expected_status:
            raise FinalizeError("last-kmsg stophud did not terminate at first success")
        stop_payload, _ = _runtime_frame(
            frame,
            f"stophud_{index}",
            ("stophud",),
            f"last-kmsg stophud[{index}]",
            expected_rc=str(expected_rc),
            expected_status=expected_status,
            max_bytes=MAX_RECEIPT_BYTES,
        )
        try:
            validate_stophud_payload(stop_payload, rc, status)
        except BaseException as exc:
            raise FinalizeError("last-kmsg stophud payload is not canonical") from exc
        for key in (
            "payload_size",
            "payload_sha256",
            "transcript_size",
            "transcript_sha256",
        ):
            if attempt.get(key) != frame.get(key):
                raise FinalizeError("last-kmsg stophud attempt/frame binding differs")
        if rc == -16:
            busy_retries += 1
    if stophud.get("busy_retries") != busy_retries:
        raise FinalizeError("last-kmsg stophud retry summary is not exact")
    if journal.get("stophud") != stophud:
        raise FinalizeError("last-kmsg journal stophud summary differs")
    if journal.get("stophud_frames") != frames:
        raise FinalizeError("last-kmsg journal stophud frames differ")
    if journal.get("stophud_attempts") != attempts:
        raise FinalizeError("last-kmsg journal stophud attempts differ")
    if public.get("stophud_accepted") is not True:
        raise FinalizeError("last-kmsg public stophud accepted summary is missing")
    if public.get("stophud_busy_retries") != busy_retries:
        raise FinalizeError("last-kmsg public stophud retry summary differs")
    if public.get("stophud_device_state_write") is not True:
        raise FinalizeError("last-kmsg public stophud state-write summary is missing")


def _runtime_validate_stophud(
    value: Mapping[str, object], raw: Mapping[str, object], journal: Mapping[str, object]
) -> None:
    stophud = raw.get("stophud")
    if not isinstance(stophud, Mapping) or stophud.get("accepted") is not True:
        raise FinalizeError("runtime stophud accepted result is missing")
    attempts = stophud.get("attempts")
    frames = raw.get("stophud_frames")
    if (
        not isinstance(attempts, list)
        or not isinstance(frames, list)
        or len(attempts) != len(frames)
        or not attempts
        or len(attempts) > STOPHUD_MAX_ATTEMPTS
    ):
        raise FinalizeError("runtime stophud attempts/frames are incomplete")
    busy = 0
    final_index = len(attempts)
    for index, (attempt, frame) in enumerate(zip(attempts, frames), 1):
        if not isinstance(attempt, Mapping):
            raise FinalizeError("runtime stophud attempt is not an object")
        if attempt.get("attempt") != index or attempt.get("evidence_id") != f"stophud_{index}":
            raise FinalizeError("runtime stophud attempt identity is not exact")
        attempt_rc = attempt.get("rc")
        attempt_status = attempt.get("status")
        if type(attempt_rc) is not int or not isinstance(attempt_status, str):
            raise FinalizeError("runtime stophud attempt terminal is malformed")
        # The arbiter terminates at the first successful stophud exchange.
        # Therefore every nonterminal retained attempt must be the explicit
        # busy refusal, and the sole terminal attempt must be 0/ok.  Accepting
        # an early success followed by more attempts would allow a replay or
        # stale retry sequence to masquerade as one bounded lifecycle.
        expected_rc = "-16" if index < final_index else "0"
        expected_status = "busy" if index < final_index else "ok"
        if attempt_rc != (-16 if index < final_index else 0) or attempt_status != expected_status:
            raise FinalizeError("runtime stophud attempts do not terminate at first success")
        stop_payload, _ = _runtime_frame(
            frame,
            f"stophud_{index}",
            ("stophud",),
            f"runtime stophud[{index}]",
            expected_rc=expected_rc,
            expected_status=expected_status,
        )
        try:
            validate_stophud_payload(stop_payload, attempt_rc, attempt_status)
        except BaseException as exc:
            raise FinalizeError("runtime stophud payload is not canonical") from exc
        if attempt_rc == -16 and attempt_status == "busy":
            busy += 1
        if attempt.get("payload_sha256") != frame.get("payload_sha256") or attempt.get("payload_size") != frame.get("payload_size") or attempt.get("transcript_sha256") != frame.get("transcript_sha256") or attempt.get("transcript_size") != frame.get("transcript_size"):
            raise FinalizeError("runtime stophud attempt/frame hash binding differs")
    if stophud.get("busy_retries") != busy:
        raise FinalizeError("runtime stophud terminal/retry summary is not exact")
    if raw.get("stophud") != journal.get("stophud") or raw.get("stophud_frames") != journal.get("stophud_frames") or stophud.get("attempts") != journal.get("stophud_attempts"):
        raise FinalizeError("runtime stophud journal binding differs")
    public_stophud = value.get("stophud")
    if public_stophud != dict(stophud):
        raise FinalizeError("runtime public stophud summary differs from private")
    public_frames = value.get("stophud_frames")
    if not isinstance(public_frames, list) or len(public_frames) != len(frames):
        raise FinalizeError("runtime public stophud frames are missing")
    for expected, public in zip(frames, public_frames):
        if not isinstance(public, Mapping):
            raise FinalizeError("runtime public stophud frame is malformed")
        projected = {key: expected[key] for key in ("evidence_id", "argv", "begin", "end", "payload_sha256", "payload_size", "transcript_sha256", "transcript_size")}
        if dict(public) != projected:
            raise FinalizeError("runtime public stophud frame binding differs")


def validate_runtime_health(path: Path, root: Path) -> dict[str, object]:
    """Validate the complete private transport journal behind final health."""

    value, data, checked = _load_evidence_json(path, root, "final rollback runtime health")
    if checked != (root / MANIFEST_ROOT_NAME / RUNTIME_HEALTH_MANIFEST_NAME).resolve(strict=False):
        raise FinalizeError("runtime health path is not the fixed V024 producer")
    if value.get("schema") != "sdm855-a90-runtime-health-public-v2":
        raise FinalizeError("runtime health schema is not exact")
    if value.get("experiment_id") != RUNTIME_HEALTH_EXPERIMENT_ID:
        raise FinalizeError("runtime health experiment ID is not the fixed V024 producer")
    for key, expected in {
        "transport_module": "tools.a90_pa28_live",
        "transport_source": "tools/a90_pa28_live.py",
        "target_verified": True,
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": TARGET_RUNTIME,
        "version": f"A90 Linux init {TARGET_RUNTIME}",
        "build": TARGET_RUNTIME_BUILD,
        "kernel": TARGET_KERNEL,
        "bootloader": TARGET_BOOTLOADER,
        "cmdline_debug_level": "0x4f4c",
        "cmdline_force_upload": "0x0",
        "cmdline_dump_sink": "0x0",
        "panic_on_oops": 1,
        "soc_id": 339,
        "boot_prefix_sha256": ROLLBACK_SHA256,
        "boot_prefix_size": BOOT_PREFIX_SIZE,
        "persistent_writes": False,
        "partition_writes": False,
        "mmio_writes": False,
        "controller_writes": False,
        "security_state_writes": False,
        "temporary_filesystem_mutations": True,
        "temporary_block_node_mutations": True,
        "stophud_device_state_write": True,
        "bridge_binding_verified": True,
    }.items():
        _require(value, key, expected, "runtime health")
    if value.get("health_scope") != "FINAL_ROLLBACK_ONLY":
        raise FinalizeError("runtime health scope is not final rollback")
    public_completed = _utc(value.get("completed_utc"), "runtime health")
    private_record = value.get("private_record")
    if not isinstance(private_record, Mapping) or private_record.get("filename") != f"{RUNTIME_HEALTH_EXPERIMENT_ID}.json" or private_record.get("journal_filename") != f"{RUNTIME_HEALTH_EXPERIMENT_ID}.journal.json":
        raise FinalizeError("runtime health private filenames are not fixed")
    raw_path = _private_path(root / PRIVATE_ROOT_NAME / f"{RUNTIME_HEALTH_EXPERIMENT_ID}.json", root, "runtime health raw")
    journal_path = _private_path(root / PRIVATE_ROOT_NAME / f"{RUNTIME_HEALTH_EXPERIMENT_ID}.journal.json", root, "runtime health journal")
    raw, raw_bytes, _ = _json(raw_path, root=root / PRIVATE_ROOT_NAME, label="runtime health raw")
    journal, journal_bytes, _ = _json(journal_path, root=root / PRIVATE_ROOT_NAME, label="runtime health journal")
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    journal_hash = hashlib.sha256(journal_bytes).hexdigest()
    if value.get("raw_snapshot_sha256") != raw_hash or value.get("raw_snapshot_size") != len(raw_bytes) or value.get("journal_sha256") != journal_hash or value.get("journal_size") != len(journal_bytes):
        raise FinalizeError("runtime health raw/journal hash binding differs")
    for owner, label in ((raw, "runtime health raw"), (journal, "runtime health journal")):
        if owner.get("schema") != "sdm855-a90-runtime-health-private-v2" or owner.get("experiment_id") != RUNTIME_HEALTH_EXPERIMENT_ID:
            raise FinalizeError(f"{label} schema/experiment is not exact")
        if owner.get("transport_module") != "tools.a90_pa28_live" or owner.get("transport_source") != "tools/a90_pa28_live.py":
            raise FinalizeError(f"{label} transport provenance is not exact")
    if raw.get("health_scope") != "FINAL_ROLLBACK_ONLY":
        raise FinalizeError("runtime health raw scope is not final rollback")
    if raw.get("completed_utc") != value.get("completed_utc") or journal.get("completed_utc") != value.get("completed_utc"):
        raise FinalizeError("runtime health completion is not hash-bound")
    if journal.get("status") != "COMPLETE" or journal.get("effect_dispatched") is not False or journal.get("effect_replayed") is not False or journal.get("raw_sha256") != raw_hash or journal.get("raw_size") != len(raw_bytes):
        raise FinalizeError("runtime health journal is not complete/hash-bound")
    for binding_key in (
        "bridge_binding",
        "post_stophud_bridge_binding",
        "final_bridge_binding",
    ):
        raw_binding = raw.get(binding_key)
        journal_binding = journal.get(binding_key)
        if not isinstance(raw_binding, Mapping) or not isinstance(journal_binding, Mapping):
            raise FinalizeError(f"runtime {binding_key} is missing from raw/journal")
        if not _runtime_binding_equal(raw_binding, journal_binding):
            raise FinalizeError(f"runtime {binding_key} differs between raw and journal")

    raw_target = raw.get("target")
    if not isinstance(raw_target, Mapping):
        raise FinalizeError("runtime health private target is missing")
    for key, expected in {
        "model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
        "bootloader": TARGET_BOOTLOADER,
        "soc_id": 339,
        "panic_on_oops": 1,
    }.items():
        _require(raw_target, key, expected, "runtime health private target")
    version_obj = raw_target.get("version")
    if version_obj != {"version": TARGET_RUNTIME, "build": TARGET_RUNTIME_BUILD}:
        raise FinalizeError("runtime health version/build provenance is not exact")
    raw_cmdline = raw_target.get("cmdline")
    if not isinstance(raw_cmdline, Mapping):
        raise FinalizeError("runtime health private cmdline is missing")
    cmdline_payloads: dict[str, bytes] = {}

    raw_records = raw.get("records")
    if not isinstance(raw_records, list) or len(raw_records) != len(_RUNTIME_EXPECTED_COMMANDS):
        raise FinalizeError("runtime health raw records are missing or incomplete")
    if journal.get("records") != raw_records:
        raise FinalizeError("runtime health journal records are not identical")
    public_records = value.get("records")
    if not isinstance(public_records, list) or len(public_records) != len(raw_records):
        raise FinalizeError("runtime health public records are missing or incomplete")
    payloads: list[bytes] = []
    for index, ((evidence_id, expected_argv), record) in enumerate(zip(_RUNTIME_EXPECTED_COMMANDS, raw_records)):
        argv = _runtime_expected_argv(
            evidence_id, expected_argv, record, f"runtime record[{index}]"
        )
        payload, _ = _runtime_frame(record, evidence_id, argv, f"runtime record[{index}]")
        payloads.append(payload)
        if public_records[index] != _runtime_public_record(record):
            raise FinalizeError(f"runtime public record[{index}] differs from private")

    # Bind decoded target summaries to the actual version/cmdline/soc/panic
    # exchanges rather than trusting self-authored public fields.
    runtime_version_identity = _parse_v024_version_payload(
        payloads[0], "runtime version"
    )
    if raw_target.get("version") != {
        "version": runtime_version_identity["runtime_version"],
        "build": runtime_version_identity["runtime_build"],
    }:
        raise FinalizeError("runtime target version/build differs from decoded payload")
    if raw_target.get("kernel") != runtime_version_identity["kernel"]:
        raise FinalizeError("runtime target kernel differs from decoded payload")
    _runtime_cmdline(payloads[1])
    if raw_cmdline != _runtime_cmdline(payloads[1]):
        raise FinalizeError("runtime raw cmdline summary differs from decoded payload")
    _runtime_line(payloads[2], b"339", "runtime soc_id")
    _runtime_line(payloads[3], b"1", "runtime panic_on_oops")

    # Exact attestation-frame subsets are retained in private raw evidence and
    # journal, while the public summary is only accepted when it matches those
    # decoded frames and fixed paths.
    boot_frame_count = 25
    boot_expected = _RUNTIME_EXPECTED_COMMANDS[4 : 4 + boot_frame_count]
    boot_frames = raw.get("boot_attestation_frames")
    boot_payloads = _runtime_validate_frame_set(boot_frames, boot_expected, "runtime boot attestation")
    journal_boot = journal.get("boot_attestation")
    if not isinstance(journal_boot, Mapping) or journal_boot.get("frames") != boot_frames:
        raise FinalizeError("runtime journal boot-attestation frames differ")
    boot = raw.get("boot_attestation")
    if not isinstance(boot, Mapping):
        raise FinalizeError("runtime boot attestation summary is missing")
    runtime_boot_uevent = _semantic_uevent_payload(
        boot_payloads[10], "runtime boot uevent"
    )
    runtime_boot_stat = {
        **_RUNTIME_BOOT_EXPECTED_STAT_BASE,
        "rdev": f"{runtime_boot_uevent['MAJOR']}:{runtime_boot_uevent['MINOR']}",
    }
    for key, expected in {
        "sysfs_root": _RUNTIME_BOOT_SYSFS_ROOT,
        "block_node": "/dev/block/sda24",
        "attest_node": _RUNTIME_BOOT_NODE,
        "attest_file": _RUNTIME_BOOT_FILE,
        "bs": 4096,
        "count": 14864,
        "expected_size": BOOT_PREFIX_SIZE,
        "captured_size": BOOT_PREFIX_SIZE,
        "expected_sha256": ROLLBACK_SHA256,
        "captured_sha256": ROLLBACK_SHA256,
        "sectors": 131072,
        "ro": 0,
        "hash_matches_candidate": True,
        "size_matches_candidate": True,
        "cleanup_ok": True,
        "cleanup_error": None,
        "binding_failure": False,
        "pre_cleanup_error": None,
        "sysfs_uevent": runtime_boot_uevent,
        "stat": runtime_boot_stat,
    }.items():
        _require(boot, key, expected, "runtime boot attestation")
    events = boot.get("binding_events")
    bridge_binding = raw.get("bridge_binding")
    if not isinstance(bridge_binding, Mapping):
        raise FinalizeError("runtime private bridge binding is missing")
    if (
        not isinstance(events, list)
        or tuple(item.get("stage") for item in events if isinstance(item, Mapping))
        != _RUNTIME_BOOT_BINDING_STAGES
        or len(events) != len(_RUNTIME_BOOT_BINDING_STAGES)
    ):
        raise FinalizeError("runtime boot-attestation bridge binding events are incomplete")
    for item in events:
        if not isinstance(item, Mapping) or not isinstance(item.get("bridge_binding"), Mapping):
            raise FinalizeError("runtime boot-attestation bridge binding event is malformed")
        if not _runtime_binding_equal(bridge_binding, item["bridge_binding"]):
            raise FinalizeError("runtime boot-attestation bridge binding drifted")
    # Bind frame payloads to the attestation summaries.  The exact dynamic
    # dev_t must agree across the uevent, mknod argv, stat rdev, and summary.
    runtime_mknod_argv = _runtime_expected_argv(
        "boot_attest_mknod",
        None,
        boot_frames[14],
        "runtime boot mknod",
    )
    if runtime_mknod_argv[2:] != (
        runtime_boot_uevent["MAJOR"],
        runtime_boot_uevent["MINOR"],
    ):
        raise FinalizeError("runtime boot mknod dev_t differs from uevent")
    _runtime_line(boot_payloads[11], b"131072", "runtime boot sector count")
    _runtime_line(boot_payloads[12], b"0", "runtime boot read-only flag")
    try:
        stat_value = inline_parse_stat_identity(
            boot_payloads[15],
            runtime_boot_uevent["MAJOR"],
            runtime_boot_uevent["MINOR"],
        )
    except BaseException as exc:
        raise FinalizeError("runtime boot stat payload is malformed") from exc
    if stat_value != runtime_boot_stat:
        raise FinalizeError("runtime boot stat differs from the fixed partition")
    if boot_payloads[14] != b"":
        raise FinalizeError("runtime boot mknod returned unexpected payload")
    if _runtime_toybox_body(boot_payloads[16], "runtime boot capture") != b"":
        raise FinalizeError("runtime boot capture has an unexpected command body")
    if _runtime_toybox_body(boot_payloads[17], "runtime boot hash") != f"{ROLLBACK_SHA256}  {_RUNTIME_BOOT_FILE}".encode("ascii"):
        raise FinalizeError("runtime boot hash frame is not bound to rollback candidate")
    if _runtime_toybox_body(boot_payloads[18], "runtime boot size") != f"{BOOT_PREFIX_SIZE} {_RUNTIME_BOOT_FILE}".encode("ascii"):
        raise FinalizeError("runtime boot size frame is not bound to rollback candidate")
    for index in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 19, 20, 21, 22, 23, 24):
        if _runtime_toybox_body(boot_payloads[index], f"runtime boot frame {index}") != b"":
            raise FinalizeError(f"runtime boot frame {index} has an unexpected command body")
    expected_journal_boot = dict(boot)
    expected_journal_boot["frames"] = boot_frames
    if any(journal_boot.get(key) != expected for key, expected in expected_journal_boot.items()):
        raise FinalizeError("runtime journal boot-attestation summary differs")
    public_boot = value.get("boot_attestation")
    if not isinstance(public_boot, Mapping):
        raise FinalizeError("runtime public boot-attestation summary is missing")
    for key, expected in {
        "expected_sha256": ROLLBACK_SHA256,
        "captured_sha256": ROLLBACK_SHA256,
        "captured_size": BOOT_PREFIX_SIZE,
        "cleanup_ok": True,
        "hash_matches_candidate": True,
        "size_matches_candidate": True,
        "binding_event_count": len(_RUNTIME_BOOT_BINDING_STAGES),
    }.items():
        _require(public_boot, key, expected, "runtime public boot attestation")

    absence = raw.get("v024_temp_absence")
    expected_temp_paths_sha256 = hashlib.sha256(
        _runtime_json_bytes(_RUNTIME_TEMP_PATHS)
    ).hexdigest()
    if (
        not isinstance(absence, Mapping)
        or absence.get("paths") != _RUNTIME_TEMP_PATHS
        or absence.get("paths_count") != 5
        or absence.get("absence_verified") is not True
        or absence.get("frame_count") != 10
        or absence.get("paths_sha256") != expected_temp_paths_sha256
    ):
        raise FinalizeError("runtime temporary absence summary is not exact")
    temp_expected = _RUNTIME_EXPECTED_COMMANDS[4 + boot_frame_count : 4 + boot_frame_count + 10]
    temp_frames = raw.get("v024_temp_absence_frames")
    temp_payloads = _runtime_validate_frame_set(temp_frames, temp_expected, "runtime temporary absence")
    journal_absence = journal.get("v024_temp_absence")
    if not isinstance(journal_absence, Mapping) or journal_absence.get("frames") != temp_frames:
        raise FinalizeError("runtime journal temporary absence frames differ")
    expected_journal_absence = dict(absence)
    expected_journal_absence["frames"] = temp_frames
    if any(journal_absence.get(key) != expected for key, expected in expected_journal_absence.items()):
        raise FinalizeError("runtime journal temporary absence summary differs")
    for index, payload in enumerate(temp_payloads):
        if _runtime_toybox_body(payload, f"runtime temporary absence frame {index}") != b"":
            raise FinalizeError(f"runtime temporary absence frame {index} has an unexpected command body")
    public_absence = value.get("v024_temp_absence")
    if not isinstance(public_absence, Mapping) or public_absence.get("paths_count") != 5 or public_absence.get("absence_verified") is not True or public_absence.get("frame_count") != 10 or public_absence.get("paths_sha256") != expected_temp_paths_sha256:
        raise FinalizeError("runtime public temporary absence summary is not exact")
    if public_absence.get("paths_sha256") != expected_temp_paths_sha256:
        raise FinalizeError("runtime public temporary path hash is not exact")

    selftest = raw.get("selftest")
    if not isinstance(selftest, Mapping) or any(selftest.get(key) != expected for key, expected in SELFTEST_EXPECTED.items()) or type(selftest.get("duration")) is not int or selftest.get("duration") < 0:
        raise FinalizeError("runtime selftest summary is not exact")
    selftest_payload = payloads[-2]
    try:
        text = selftest_payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FinalizeError("runtime selftest payload is not ASCII") from exc
    match = re.fullmatch(r"selftest: pass=([0-9]+) warn=([0-9]+) fail=([0-9]+) duration=([0-9]+)ms entries=([0-9]+)\r?\n?", text)
    if match is None:
        raise FinalizeError("runtime selftest payload is not complete")
    decoded_selftest = {"passed": int(match.group(1)), "warn": int(match.group(2)), "fail": int(match.group(3)), "duration": int(match.group(4)), "entries": int(match.group(5))}
    if decoded_selftest != dict(selftest):
        raise FinalizeError("runtime selftest summary differs from decoded payload")
    battery = raw.get("battery_capacity_percent")
    if type(battery) is not int or not 0 <= battery <= 100:
        raise FinalizeError("runtime battery summary is malformed")
    battery_payload = payloads[-1]
    battery_text = battery_payload.decode("ascii", errors="strict").rstrip("\r\n")
    if not re.fullmatch(r"[0-9]+", battery_text) or int(battery_text) != battery:
        raise FinalizeError("runtime battery summary differs from decoded payload")
    if value.get("selftest") != dict(selftest) or value.get("battery_capacity_percent") != battery:
        raise FinalizeError("runtime public selftest/battery summary differs from private")

    _runtime_validate_stophud(value, raw, journal)
    writes = raw.get("device_writes")
    if not isinstance(writes, Mapping):
        raise FinalizeError("runtime health device_writes is missing")
    for key, expected in {
        "stophud": True,
        "temporary_filesystem_mutations": True,
        "temporary_block_node_mutations": True,
        "partition_writes": False,
        "mmio_writes": False,
        "controller_writes": False,
        "security_state_writes": False,
        "persistent_writes": False,
    }.items():
        _require(writes, key, expected, "runtime private device_writes")
    if writes.get("temporary_mutation_paths") != _RUNTIME_TEMP_PATHS:
        raise FinalizeError("runtime private temporary mutation paths are not exact")
    if writes.get("temporary_mutation_operations") != [
        "mkdir",
        "mknodb",
        "dd_to_temp",
        "rm",
        "absence_checks",
    ]:
        raise FinalizeError("runtime private temporary mutation operations are not exact")
    public_writes = value.get("device_writes")
    if not isinstance(public_writes, Mapping):
        raise FinalizeError("runtime public device_writes is missing")
    for key, expected in {
        "stophud": True,
        "temporary_filesystem_mutations": True,
        "temporary_block_node_mutations": True,
        "partition_writes": False,
        "mmio_writes": False,
        "controller_writes": False,
        "security_state_writes": False,
        "persistent_writes": False,
    }.items():
        _require(public_writes, key, expected, "runtime public device_writes")
    return {
        "kind": "runtime_health",
        "experiment_id": RUNTIME_HEALTH_EXPERIMENT_ID,
        "path": str(checked),
        **_receipt_hash(data),
        "raw_sha256": raw_hash,
        "raw_size": len(raw_bytes),
        "journal_sha256": journal_hash,
        "journal_size": len(journal_bytes),
        "completed_utc": value["completed_utc"],
    }


def _fsync_directory(path: Path) -> None:
    """Fsync one already-validated output directory."""

    directory_fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _inode_identity(st: os.stat_result, label: str) -> tuple[int, int, int, int]:
    """Return the identity needed to bind a staged regular inode."""

    if not stat.S_ISREG(st.st_mode):
        raise FinalizeError(f"{label} is not a regular file")
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_size)


def _fd_identity(fd: int, label: str) -> tuple[int, int, int, int]:
    try:
        return _inode_identity(os.fstat(fd), label)
    except OSError as exc:
        raise FinalizeError(f"{label} staged file cannot be inspected") from exc


def _fd_digest(fd: int, label: str) -> str:
    """Hash the retained FD without trusting its pathname or current offset."""

    identity = _fd_identity(fd, label)
    size = identity[3]
    try:
        if hasattr(os, "pread"):
            data = os.pread(fd, size, 0)
        else:
            current = os.lseek(fd, 0, os.SEEK_CUR)
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                chunks: list[bytes] = []
                remaining = size
                while remaining:
                    chunk = os.read(fd, remaining)
                    if not chunk:
                        raise FinalizeError(f"{label} was truncated while hashing")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
            finally:
                os.lseek(fd, current, os.SEEK_SET)
    except OSError as exc:
        raise FinalizeError(f"{label} cannot be hashed") from exc
    if len(data) != size:
        raise FinalizeError(f"{label} changed while hashing")
    return hashlib.sha256(data).hexdigest()


def _open_final_and_digest(
    path: Path,
    identity: tuple[int, int, int, int],
    expected_digest: str,
    label: str,
) -> None:
    """Open the final inode without following links and hash its bytes."""

    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise FinalizeError(f"{label} cannot be opened without following links") from exc
    try:
        if _fd_identity(fd, label) != identity:
            raise FinalizeError(f"{label} inode differs from retained staged inode")
        if _fd_digest(fd, label) != expected_digest:
            raise FinalizeError(f"{label} digest differs from staged data")
        if _fd_identity(fd, label) != identity:
            raise FinalizeError(f"{label} changed while being hashed")
    finally:
        os.close(fd)


def _path_identity(path: Path, label: str) -> tuple[int, int, int, int]:
    try:
        return _inode_identity(os.lstat(path), label)
    except OSError as exc:
        raise FinalizeError(f"{label} staged path cannot be inspected") from exc


def _require_unlinked(path: Path, label: str) -> None:
    """Prove the staged pathname disappeared after its unlink."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise FinalizeError(f"{label} staged pathname cannot be reconciled") from exc
    raise FinalizeError(f"{label} staged pathname was replaced during cleanup")


def _stage_output(
    path: Path, data: bytes, mode: int
) -> tuple[int, tuple[int, int, int, int], str]:
    """Create/fsync one O_EXCL temp and retain its FD through publication."""

    temporary = path.with_name(path.name + ".tmp")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(temporary, flags, mode)
    except OSError as exc:
        raise FinalizeError(f"cannot create exclusive staged output: {temporary}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise FinalizeError(f"short write while staging {temporary}")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
        identity = _fd_identity(fd, f"{temporary} staged inode")
        digest = _fd_digest(fd, f"{temporary} staged inode")
        expected_digest = hashlib.sha256(data).hexdigest()
        if digest != expected_digest:
            raise FinalizeError(f"{temporary} staged digest differs from input data")
        return fd, identity, expected_digest
    except BaseException:
        os.close(fd)
        raise


def _publish_temp_noreplace(
    temporary: Path,
    final: Path,
    *,
    staged_fd: int | None = None,
    staged_identity: tuple[int, int, int, int] | None = None,
    staged_digest: str | None = None,
) -> None:
    """Publish a staged file without replacing a concurrently-created final.

    ``os.replace`` is atomic but destructive: a second owner can win a race
    after the caller's precheck and silently overwrite the first receipt.
    A same-directory hard link gives us an atomic create-if-absent operation;
    the staged inode remains available when the destination collides so the
    operator can reconcile the race rather than losing evidence.
    """

    owns_fd = staged_fd is None
    fd = staged_fd
    if fd is None:
        try:
            fd = os.open(
                temporary,
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            raise FinalizeError(f"cannot retain staged output FD: {temporary}") from exc
    assert fd is not None
    try:
        identity = staged_identity or _fd_identity(fd, f"{temporary} staged inode")
        digest = staged_digest or _fd_digest(fd, f"{temporary} staged inode")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise FinalizeError(f"{temporary} staged digest is malformed")
        if _fd_identity(fd, f"{temporary} staged inode") != identity:
            raise FinalizeError(f"{temporary} staged inode changed before publication")
        if _path_identity(temporary, f"{temporary} staged path") != identity:
            raise FinalizeError(f"{temporary} staged path was substituted before publication")
        if _fd_digest(fd, f"{temporary} staged inode") != digest:
            raise FinalizeError(f"{temporary} staged digest changed before publication")
        os.link(temporary, final, follow_symlinks=False)
    except FileExistsError as exc:
        if owns_fd:
            os.close(fd)
        raise FinalizeError(
            f"finalizer output appeared during publication: {final}"
        ) from exc
    except OSError as exc:
        # Some platforms report EEXIST as a plain OSError subclass.  Keep the
        # staged temp in place for either collision/error path.
        if getattr(exc, "errno", None) == getattr(os, "EEXIST", 17):
            if owns_fd:
                os.close(fd)
            raise FinalizeError(
                f"finalizer output appeared during publication: {final}"
            ) from exc
        if owns_fd:
            os.close(fd)
        raise
    except BaseException:
        if owns_fd:
            os.close(fd)
        raise
    try:
        # The hard-link target must still be exactly the retained staged inode;
        # a same-UID substitution of either pathname must never be reported as
        # a successful publication.
        if _fd_identity(fd, f"{temporary} staged inode") != identity:
            raise FinalizeError(f"{temporary} staged inode changed after publication")
        if _path_identity(temporary, f"{temporary} staged path") != identity:
            raise FinalizeError(f"{temporary} staged path was substituted after publication")
        if _path_identity(final, f"{final} published path") != identity:
            raise FinalizeError(f"{final} published inode is not the retained staged inode")
        if _fd_digest(fd, f"{temporary} staged inode") != digest:
            raise FinalizeError(f"{temporary} staged digest changed after publication")
        _open_final_and_digest(
            final, identity, digest, f"{final} published path"
        )
        os.unlink(temporary)
        _require_unlinked(temporary, f"{temporary} cleanup")
        _fsync_directory(final.parent)
    except BaseException:
        # On collision, substitution, or cleanup failure retain the temp and
        # any winner for deterministic reconciliation.  The caller closes the
        # retained FD after this function returns/raises.
        raise
    finally:
        if owns_fd:
            os.close(fd)


def _write_new(path: Path, data: bytes, mode: int) -> None:
    _reject_symlink_components(path.parent, "finalizer output")
    if path.exists() or path.is_symlink():
        raise FinalizeError(f"finalizer output already exists: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FinalizeError(f"finalizer output temporary already exists: {temporary}")
    fd, identity, digest = _stage_output(path, data, mode)
    try:
        _publish_temp_noreplace(
            temporary,
            path,
            staged_fd=fd,
            staged_identity=identity,
            staged_digest=digest,
        )
    except BaseException as exc:
        if isinstance(exc, FinalizeError):
            raise
        raise FinalizeError(f"published {path} but directory durability failed") from exc
    finally:
        os.close(fd)


def _write_pair(
    private_path: Path,
    private_data: bytes,
    public_path: Path,
    public_data: bytes,
) -> None:
    """Stage both outputs, then publish no-clobber pair with recovery evidence.

    Cross-directory publication is not atomic on POSIX.  Both files are
    therefore fully written/fsynced to unique ``.tmp`` paths before either
    same-directory hard-link publication.  If the second link fails, the
    first final and the remaining public temp are deliberately retained so an
    operator can reconcile rather than a replay silently overwriting
    evidence.
    """

    for path in (private_path, public_path):
        _reject_symlink_components(path.parent, "finalizer output")
        if path.exists() or path.is_symlink():
            raise FinalizeError(f"finalizer output already exists: {path}")
        temp = path.with_name(path.name + ".tmp")
        if temp.exists() or temp.is_symlink():
            raise FinalizeError(f"finalizer output temporary already exists: {temp}")
    # Stage both files first and retain both descriptors until their
    # respective hard-link publication has completed.  If the public link
    # collides, the private winner and public temp remain reconcilable.
    staged: list[tuple[Path, Path, int, tuple[int, int, int, int], str]] = []
    try:
        for path, data, mode in (
            (private_path, private_data, 0o600),
            (public_path, public_data, 0o644),
        ):
            fd, identity, digest = _stage_output(path, data, mode)
            staged.append(
                (path, path.with_name(path.name + ".tmp"), fd, identity, digest)
            )
        for path, temporary, fd, identity, digest in staged:
            _publish_temp_noreplace(
                temporary,
                path,
                staged_fd=fd,
                staged_identity=identity,
                staged_digest=digest,
            )
    finally:
        for _path, _temporary, fd, _identity, _digest in staged:
            os.close(fd)


def finalize(args: argparse.Namespace) -> tuple[Path, Path]:
    # Root and every producer selector are resolved before any output
    # directory is created.  This makes an injected alternate namespace or a
    # cross-spliced receipt a pre-validation refusal, not an INCIDENT emitted
    # from a second evidence universe.
    experiment_id = getattr(args, "experiment_id", None)
    if experiment_id != FINAL_EXPERIMENT_ID:
        raise FinalizeError(
            "finalizer experiment ID is fixed to verification-024-final"
        )
    root = _fixed_output_root(args)
    inputs = _fixed_chain_inputs(args, root)
    private_dir = root / PRIVATE_ROOT_NAME
    public_dir = root / MANIFEST_ROOT_NAME
    _reject_symlink_components(private_dir, "private evidence root")
    _reject_symlink_components(public_dir, "public manifest root")
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    public_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    private_path = _private_path(private_dir / f"{experiment_id}.finalizer.json", root, "finalizer private output")
    public_path = _path_under(public_dir / f"{experiment_id}.finalizer.manifest.json", root / MANIFEST_ROOT_NAME, "finalizer public output")
    if private_path.exists() or public_path.exists() or private_path.with_name(private_path.name + ".tmp").exists() or public_path.with_name(public_path.name + ".tmp").exists():
        raise FinalizeError("finalizer output already exists; replay forbidden")
    validators = (
        ("control", lambda: validate_control(inputs["control_manifest"], root)),
        ("read", lambda: validate_read(inputs["read_manifest"], root, results["control"])),
        ("last_kmsg", lambda: validate_last_kmsg(inputs["last_kmsg"], root)),
        ("rollback_flash", lambda: validate_rollback_flash(inputs["rollback_flash"], root)),
        ("rollback_system_boot", lambda: validate_system_boot(inputs["rollback_system_boot"], root)),
        ("param_capture", lambda: validate_param_capture(inputs["param_capture"], root)),
        ("runtime_health", lambda: validate_runtime_health(inputs["runtime_health"], root)),
    )
    results: dict[str, dict[str, object]] = {}
    failures: dict[str, str] = {}
    for name, validator in validators:
        try:
            results[name] = validator()
        except BaseException as exc:
            failures[name] = f"{type(exc).__name__}: {exc}"
    chronology = ("control", "read", "last_kmsg", "rollback_flash", "rollback_system_boot", "param_capture", "runtime_health")
    if not failures:
        try:
            points = [_utc(results[name].get("completed_utc"), name) for name in chronology]
            if any(left >= right for left, right in zip(points, points[1:])):
                raise FinalizeError("receipt chronology is not strictly control<read<reset<rollback<system<param<health")
        except BaseException as exc:
            failures["chronology"] = f"{type(exc).__name__}: {exc}"
    if "read" in results and "last_kmsg" in results:
        try:
            read_result = results["read"]
            last_result = results["last_kmsg"]
            source = last_result.get("read_source")
            if not isinstance(source, Mapping):
                raise FinalizeError("last-kmsg source join is missing")
            if source.get("experiment_id") != read_result.get("experiment_id"):
                raise FinalizeError("last-kmsg source is not the supplied read receipt")
            for key in (
                "manifest_sha256",
                "manifest_size",
                "raw_sha256",
                "raw_size",
                "journal_sha256",
                "journal_size",
            ):
                result_key = {
                    "manifest_sha256": "sha256",
                    "manifest_size": "size",
                }.get(key, key)
                if source.get(key) != read_result.get(result_key):
                    raise FinalizeError(f"last-kmsg/read source hash field {key!r} differs")
            if source.get("completed_utc") != read_result.get("completed_utc"):
                raise FinalizeError("last-kmsg source completion is not the read completion")
            if _utc(last_result.get("completed_utc"), "last-kmsg") <= _utc(read_result.get("completed_utc"), "read"):
                raise FinalizeError("last-kmsg completion is not later than read")
        except BaseException as exc:
            failures["read_last_kmsg_join"] = f"{type(exc).__name__}: {exc}"
    # A returned value is a safety stop even when rollback or final health
    # evidence is incomplete.  Derive this only from the hash-bound private
    # read artifact, never from an outcome string or a public boolean alone.
    # Promotion is possible only when the complete independent read
    # validator succeeded.  Summary-only public/private fields, even when
    # they look like a 32-bit value, cannot manufacture a potential result
    # after the actual fixed-op frame/journal chain failed validation.
    value_present = bool(results.get("read", {}).get("value_present"))
    if value_present:
        classification = "POTENTIAL_SECURITY_BOUNDARY_BYPASS"
    elif not failures and len(results) == len(validators):
        classification = "REFUSED_AT_MID"
    else:
        classification = "INCIDENT"
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    private = {
        "schema": "sdm855-a90-verification024-finalizer-private-v1",
        "experiment_id": experiment_id,
        "started_utc": started,
        "completed_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "classification": classification,
        "failures": failures,
        "receipts": results,
        "host_only": True,
        "device_contact": False,
        "replay": False,
    }
    private_bytes = json.dumps(private, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(private_bytes) > MAX_OUTPUT_BYTES:
        raise FinalizeError("finalizer private output exceeds bound")
    public = {
        "schema": "sdm855-a90-verification024-finalizer-public-v1",
        "experiment_id": experiment_id,
        "completed_utc": private["completed_utc"],
        "classification": classification,
        "target_verified": not failures,
        "target_model": TARGET_MODEL if not failures else None,
        "target_runtime": "LOW" if not failures else None,
        "runtime": "LOW" if not failures else None,
        "tested_configuration": TARGET_DMID if not failures else None,
        "gate_results": {name: name in results for name, _ in validators},
        "gate_failures": sorted(failures),
        "receipt_hashes": {
            name: {"sha256": result["sha256"], "size": result["size"]}
            for name, result in results.items()
        },
        "returned_value_present": value_present,
        "clean_negative": classification == "REFUSED_AT_MID",
        "host_only": True,
        "device_contact": False,
        "private_snapshot_sha256": hashlib.sha256(private_bytes).hexdigest(),
        "private_snapshot_size": len(private_bytes),
        "private_record": {"filename": private_path.name, "git_ignored": True},
        "claim_boundary": (
            "Only the complete exact chain supports refusal at MID; missing or malformed evidence is an incident."
            if classification == "REFUSED_AT_MID"
            else "A returned read value is a potential security-boundary bypass; no broad-negative finalization is authorized."
            if value_present
            else "The evidence chain is incomplete or malformed; this is not a clean negative."
        ),
    }
    public_bytes = json.dumps(public, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(public_bytes) > MAX_OUTPUT_BYTES:
        raise FinalizeError("finalizer public output exceeds bound")
    _write_pair(private_path, private_bytes, public_path, public_bytes)
    return private_path, public_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--control-manifest", type=Path, required=True)
    parser.add_argument("--read-manifest", type=Path, required=True)
    parser.add_argument("--last-kmsg", type=Path, required=True)
    parser.add_argument("--rollback-flash", type=Path, required=True)
    parser.add_argument("--rollback-system-boot", type=Path, required=True)
    parser.add_argument("--param-capture", type=Path, required=True)
    parser.add_argument("--runtime-health", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    private_path, public_path = finalize(make_parser().parse_args(argv))
    print(f"private={private_path}")
    print(f"public={public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
