#!/usr/bin/env python3
"""Validate the committed, redacted Verification 024 R2 checkpoint.

Only the fixed reconciliation manifest is opened; its embedded descriptors
pin the three R2 files without reopening private data or exposing paths.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat
from typing import Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE_PATH = Path(
    "evidence/manifests/verification-024-control-r2-preflight-incident.manifest.json"
)
INCIDENT_MANIFEST_SHA256 = "ef4b3edc01b23f91e24f5ad3737b83c2922b1fc7cf9e399a31e74efb5a9e97fa"
INCIDENT_MANIFEST_SIZE = 3052
R3_MANIFEST_RELATIVE_PATH = Path(
    "evidence/manifests/verification-024-control-r3-preflight-incident.manifest.json"
)
R3_INCIDENT_MANIFEST_SHA256 = "f9fe1d81e6d38c0904b2214ec475cd963e45e40d985c8309d9145ca2ac29b92a"
R3_INCIDENT_MANIFEST_SIZE = 3455
MAX_FILE_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024

VALIDATION_SCHEMA = "sdm855-a90-v024-control-r2-incident-validation-v1"
R3_VALIDATION_SCHEMA = "sdm855-a90-v024-control-r3-incident-validation-v1"
INCIDENT_ID = "verification-024-control-r2-preflight-incident"
R2_ID = "verification-024-control-r2"
NEXT_ID = "verification-024-control-r3"
R3_INCIDENT_ID = "verification-024-control-r3-preflight-incident"
R3_ID = "verification-024-control-r3"
R3_NEXT_ID = "verification-024-control-r4"
R3_RECOVERY_DESCRIPTOR_SHA256 = (
    "29439f2d8a6dc5cbb6113ca7a8843f37940e7201a26c378ceb019fa3cbbfc149"
)
R3_RECOVERY_DESCRIPTOR_SIZE = 1879
R3_WRITEFILE_PAYLOAD_SHA256 = (
    "e71253fbda8d47143381003ab14d4887d8f214858728278267bf5daa9907e42b"
)
R3_WRITEFILE_PAYLOAD_SIZE = 13
R3_ARTIFACT_PINS: Mapping[str, tuple[str, int]] = {
    "journal": (
        "3e55bb1b85b4ab3a7c63a682a05a58220d4c26a7dfb7fbd08e2d1df8f181378e",
        79467,
    ),
    "panic_recovery": (R3_RECOVERY_DESCRIPTOR_SHA256, R3_RECOVERY_DESCRIPTOR_SIZE),
    "public": (
        "551465718605e47db02ca8b4e469ae8be2def65b79f7e8aeb5c5b7648a0606bc",
        5099,
    ),
    "raw": (
        "f0cefe3490f325761208514a665e5be506c87b9c36e01157513019b1d654dd05",
        68518,
    ),
    "semantic_claim": (
        "568e910893a831af9b9ed7d69c778a6cb03f4a27bc64a7323cdd507f940de0a3",
        512,
    ),
    "source_gate": (
        "b92b728b4be4e44ee9a84ffef45e1f2927dd780512584bef5b449e6693425adf",
        4553,
    ),
}
R4_MANIFEST_RELATIVE_PATH = Path(
    "evidence/manifests/verification-024-control-r4-returned-incident.manifest.json"
)
R4_INCIDENT_MANIFEST_SHA256 = (
    "4ff3b6db16e2290e391dc13005062fd2f3fa962ef1336adcf19fc0913c15f85b"
)
R4_INCIDENT_MANIFEST_SIZE = 4758
R4_VALIDATION_SCHEMA = "sdm855-a90-v024-control-r4-incident-validation-v1"
R4_INCIDENT_ID = "verification-024-control-r4-returned-incident"
R4_ID = "verification-024-control-r4"
R4_NEXT_ID = "verification-024-control-r5"

R4_TARGET_PINS: Mapping[str, object] = {
    "boot_id_sha256": "8953331fec3a0c638cb06e4f77fa1b6127e75f5e30d55f7e638ec5703a185dc9",
    "boot_prefix_sha256": "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247",
    "boot_prefix_size": 60882944,
    "model": "SM-A908N",
    "scope": "A90_ONLY",
    "soc": "SM8150",
}
R4_CLAIMS_PINS: Mapping[str, object] = {
    "classification": "CLASS_C_UNCHANGED",
    "controller_writes": False,
    "effect_ambiguous": False,
    "effect_dispatched": True,
    "effect_replayed": False,
    "fixed_op_dispatch_count": 1,
    "fixed_op_returned": True,
    "memory_or_mmio_writes": False,
    "panic_after_recovery": 1,
    "panic_before": 1,
    "panic_restore_verified": True,
    "partition_writes": False,
    "protected_memory_read": False,
    "r4_id_consumed": True,
    "security_boundary_result": "UNKNOWN_NOT_REACHED",
    "semantic_claim_retained": True,
    "smc": False,
}
R4_ARTIFACT_PINS: Mapping[str, Mapping[str, object]] = {
    "host_source_gate": {
        "basename": "verification-024-control-r4-host-source-gate.manifest.json",
        "sha256": "6110b5bbd94fce23e433a046598b38b117f99f6b94db6b62d0a30235e72e4730",
        "size": 6355,
    },
    "journal": {
        "basename": "verification-024-control-r4.journal.json",
        "mode": "0600",
        "sha256": "2252bdeffdec0770deb3fb456662d91a7f09aff33ee147ef1e2547beb5984807",
        "size": 108554,
    },
    "public": {
        "basename": "verification-024-control-r4.manifest.json",
        "mode": "0644",
        "sha256": "e7f09da6283d84bba0492394019d6e14c02893b3560976db6cba216944a7fbcb",
        "size": 5346,
    },
    "raw": {
        "basename": "verification-024-control-r4.json",
        "mode": "0600",
        "sha256": "d85705efac9ceac7c4acc74830eb80859eaaaea32fa33679f3583bdb88fd6b21",
        "size": 89998,
    },
    "semantic_claim": {
        "basename": "verification-024-inline-op-f490728959ac4cef0e3a4de7267db2a1c87fa351f6095af1a415c3fa4bf7b322.claim.json",
        "mode": "0600",
        "sha256": "561bc65dd24c0fabb29f5240ce137fe199acc440b44161878b546966d73ac5c2",
        "size": 512,
    },
}
R4_PANIC_TRANSITION_PINS: Mapping[str, object] = {
    "before": 1,
    "proof_frame_ids": [
        "panic_before",
        "panic_set_0",
        "panic_zero_verify",
        "panic_set_1",
        "panic_restore_verify",
    ],
    "restore_deferred": False,
    "restore_write_attempted": True,
    "restored": True,
    "zero_set": True,
    "zero_verified": True,
    "zero_write_attempted": True,
}
R4_FIXED_OP_PINS: Mapping[str, object] = {
    "a90r_marker_count": 1,
    "a90r_marker_line": "[  116.230307] [5:        busybox:  676] A90Rc071",
    "begin": {
        "argc": "5",
        "cmd": "run",
        "flags": "0x2",
        "seq": "49",
    },
    "canonical_value_candidate": "0x000000000000c071",
    "end": {
        "cmd": "run",
        "duration_ms": "702",
        "errno": "0",
        "flags": "0x2",
        "rc": "0",
        "seq": "49",
        "status": "ok",
    },
    "frame_canonical_sha256": "c4d0530cb6b60797acab56aa056f094b700d40f2d39349c5e221c383f1a7a858",
    "frame_canonical_size": 9665,
    "payload_line_count": 19,
    "payload_sha256": "0fdb2adf322e5f6848428c19430b87a39e7a6ea5081e1672c1cf9be39da44003",
    "payload_size": 1730,
    "result_grade": "RETURNED_SENTINEL_CANDIDATE_NOT_CONTROL_PASS",
    "transcript_sha256": "05ef2e84b9160ee00909b06a9bd819f4127fcc357601375ce9ddbc722f7521d6",
    "transcript_size": 4215,
}
R4_PARSER_INCIDENT_PINS: Mapping[str, object] = {
    "exception_type": "OperationReturnedError",
    "reason": (
        "The fixed operation returned one complete rc=0/status=ok frame and one "
        "prefixed A90Rc071 marker, but the payload also contained dynamic-linker "
        "diagnostics and one empty line, so the strict one-record parser refused "
        "promotion."
    ),
    "repair_precondition": (
        "Suppress child stderr before subcommands and canonicalize only one "
        "line-ending A90R token; do not broaden the parser to arbitrary noise."
    ),
}
R4_TOP_LEVEL_KEYS = (
    "artifacts",
    "claims",
    "completed_utc",
    "experiment_id",
    "fixed_op",
    "next_registered_id",
    "panic_transition",
    "parser_incident",
    "post_incident_readonly_health",
    "schema",
    "source",
    "started_utc",
    "status",
    "target",
)
R4_STARTED_UTC = "2026-08-28T10:38:40+00:00"
R4_COMPLETED_UTC = "2026-08-28T10:38:43+00:00"
R4_SOURCE_PINS: Mapping[str, object] = {
    "commit": "5395249ce31170c43a45fcf42d7d438ad2957477",
    "producer_sha256": "12c8690520e4bbd054a1e6155d700753f23eb3a20a3322552e0fc8fc69c55786",
}
R4_POST_INCIDENT_READONLY_HEALTH_PINS: Mapping[str, object] = {
    "boot_id_sha256": "8953331fec3a0c638cb06e4f77fa1b6127e75f5e30d55f7e638ec5703a185dc9",
    "bridge_process_pid": 47726,
    "debug_level": "0x494d",
    "evidence_grade": "SUPPORTED_EXEC_TRANSCRIPT",
    "force_upload": "0",
    "panic_on_oops": 1,
    "selftest": {
        "entries": 12,
        "fail": 0,
        "passed": 11,
        "warn": 1,
    },
    "target_model": "SM-A908N",
    "target_soc": "SM8150",
}


class R2IncidentError(ValueError):
    """The fixed R2 reconciliation checkpoint is not valid."""


def _lexical(path: Path | str) -> Path:
    try:
        value = Path(os.fspath(path))
    except (TypeError, ValueError) as exc:
        raise R2IncidentError("root is not a filesystem path") from exc
    if ".." in value.parts:
        raise R2IncidentError("root may not contain '..'")
    return Path(os.path.abspath(os.fspath(value)))


def _reject_links(path: Path) -> None:
    cursor = Path(path.anchor or os.sep)
    for component in path.parts[1:]:
        cursor /= component
        try:
            if stat.S_ISLNK(os.lstat(cursor).st_mode):
                raise R2IncidentError("manifest path contains a symlink")
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise R2IncidentError("manifest path cannot be inspected") from exc


def _manifest_path(
    root: Path | str,
    relative_path: Path = MANIFEST_RELATIVE_PATH,
) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise R2IncidentError("manifest path must be a fixed relative path")
    root_path = _lexical(root)
    _reject_links(root_path)
    try:
        root_info = os.lstat(root_path)
    except OSError as exc:
        raise R2IncidentError("root cannot be inspected") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise R2IncidentError("root is not a directory")
    path = _lexical(root_path / relative)
    _reject_links(path)
    return path


def _read_fixed_path(
    path: Path,
    expected_sha256: str,
    expected_size: int,
) -> tuple[bytes, dict[str, int | str]]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise R2IncidentError("O_NOFOLLOW is unavailable")
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise R2IncidentError("manifest is not a regular file")
        mode = stat.S_IMODE(before.st_mode)
        if mode & 0o111 or mode & 0o002 or not mode & 0o400:
            raise R2IncidentError("manifest mode is executable, world-writable, or unreadable")
        if before.st_nlink != 1:
            raise R2IncidentError("manifest has an unexpected hard-link count")
        if before.st_size != expected_size or before.st_size > MAX_FILE_BYTES:
            raise R2IncidentError("manifest size is not exact")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(READ_CHUNK_BYTES, MAX_FILE_BYTES - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise R2IncidentError("manifest exceeds the bounded size")
        after = os.fstat(fd)
        identity = lambda info: (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        if identity(before) != identity(after) or total != after.st_size:
            raise R2IncidentError("manifest changed while being read")
        data = b"".join(chunks)
        if len(data) != expected_size:
            raise R2IncidentError("manifest byte size is not exact")
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected_sha256:
            raise R2IncidentError("manifest SHA-256 is not exact")
        return data, {"sha256": digest, "size_bytes": len(data)}
    finally:
        os.close(fd)


def _read_fixed_manifest(
    root: Path | str,
    relative_path: Path,
    expected_sha256: str,
    expected_size: int,
) -> tuple[bytes, dict[str, int | str]]:
    """Read one fixed manifest through the common no-follow stability gate."""

    return _read_fixed_path(
        _manifest_path(root, relative_path), expected_sha256, expected_size
    )


def _read_manifest(path: Path) -> tuple[bytes, dict[str, int | str]]:
    """Compatibility wrapper for the original R2 fixed-manifest reader."""

    return _read_fixed_path(path, INCIDENT_MANIFEST_SHA256, INCIDENT_MANIFEST_SIZE)


def _json_object(data: bytes) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise R2IncidentError("manifest contains a duplicate key")
            result[key] = value
        return result

    def reject(value: str) -> object:
        raise R2IncidentError(f"manifest contains nonfinite JSON value: {value}")

    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=unique,
            parse_constant=reject,
        )
    except R2IncidentError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R2IncidentError("manifest is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise R2IncidentError("manifest root is not an object")

    def finite(item: object) -> None:
        if isinstance(item, float) and not math.isfinite(item):
            raise R2IncidentError("manifest contains nonfinite JSON value")
        if isinstance(item, dict):
            for child in item.values():
                finite(child)
        elif isinstance(item, list):
            for child in item:
                finite(child)

    finite(value)
    return value


def _get(document: Mapping[str, object], dotted: str) -> object:
    value: object = document
    for key in dotted.split("."):
        if not isinstance(value, dict) or key not in value:
            raise R2IncidentError(f"missing required field: {dotted}")
        value = value[key]
    return value


def _require(document: Mapping[str, object], dotted: str, expected: object) -> None:
    actual = _get(document, dotted)
    if expected is None:
        valid = actual is None
    elif type(expected) is bool:
        valid = type(actual) is bool and actual == expected
    elif type(expected) is int:
        valid = type(actual) is int and actual == expected
    else:
        valid = type(actual) is type(expected) and actual == expected
    if not valid:
        raise R2IncidentError(f"field {dotted} is not the pinned value")


def _pin_r4_value(actual: object, expected: object, label: str) -> None:
    """Compare an R4 value recursively, including JSON scalar types."""

    if isinstance(expected, dict):
        if type(actual) is not dict or set(actual) != set(expected):
            raise R2IncidentError(f"field {label} is not the pinned object")
        for key, value in expected.items():
            _pin_r4_value(actual[key], value, f"{label}.{key}")
        return
    if isinstance(expected, list):
        if type(actual) is not list or len(actual) != len(expected):
            raise R2IncidentError(f"field {label} is not the pinned list")
        for index, value in enumerate(expected):
            _pin_r4_value(actual[index], value, f"{label}[{index}]")
        return
    if type(actual) is not type(expected) or actual != expected:
        raise R2IncidentError(f"field {label} is not the pinned value")


def _require_r4(document: Mapping[str, object], dotted: str, expected: object) -> None:
    _pin_r4_value(_get(document, dotted), expected, dotted)


def _validate(document: Mapping[str, object]) -> None:
    expected: Mapping[str, object] = {
        "schema": "sdm855-a90-v024-control-r2-preflight-incident-v1",
        "experiment_id": INCIDENT_ID,
        "next_registered_id": NEXT_ID,
        "target.model": "SM-A908N",
        "target.scope": "A90_ONLY",
        "target.soc": "SM8150",
        "claims.classification": "CLASS_C_UNCHANGED",
        "claims.dispatch_count": 0,
        "claims.effect_dispatched": False,
        "claims.effect_ambiguous": False,
        "claims.effect_replayed": False,
        "claims.partition_writes": False,
        "claims.memory_or_mmio_writes": False,
        "claims.controller_writes": False,
        "claims.device_state_write": False,
        "claims.panic_before": 1,
        "claims.panic_zero_write_attempted": False,
        "claims.panic_zero_set": False,
        "claims.panic_zero_verified": False,
        "claims.semantic_claim_created": False,
        "claims.security_boundary_result": "UNKNOWN_NOT_REACHED",
        "claims.r2_id_consumed": True,
        "claims.same_id_reuse": False,
    }
    for dotted, value in expected.items():
        _require(document, dotted, value)
    artifacts = _get(document, "artifacts")
    if not isinstance(artifacts, dict):
        raise R2IncidentError("artifact descriptors are not an object")
    pins = {
        "public": (
            "a4bbdb56a49c483a474b12c17cc0c9433a6bbc546c4fb056063de33f49e9766e",
            4195,
            "0644",
        ),
        "raw": (
            "3f60742a07132fd391426153f84f9eba6b32ee0371136da96e581f618ba5bec3",
            50521,
            "0600",
        ),
        "journal": (
            "05917be55f4c6baa1a1762fa1d5c860360663d213aab13df4495c4a0292c5b1b",
            57178,
            "0600",
        ),
    }
    for role, fields in pins.items():
        if role not in artifacts or not isinstance(artifacts[role], dict):
            raise R2IncidentError(f"missing {role} artifact descriptor")
        digest, size, mode = fields
        actual = artifacts[role]
        for key, value in (("sha256", digest), ("size_bytes", size), ("mode", mode)):
            if actual.get(key) != value or type(actual.get(key)) is not type(value):
                raise R2IncidentError(f"{role} artifact descriptor is not pinned")


def validate_r2_incident(root: Path | str) -> dict[str, object]:
    """Validate the fixed checkpoint and return a compact redacted summary."""

    data, metadata = _read_fixed_manifest(
        root, MANIFEST_RELATIVE_PATH, INCIDENT_MANIFEST_SHA256, INCIDENT_MANIFEST_SIZE
    )
    document = _json_object(data)
    _validate(document)
    artifacts = _get(document, "artifacts")
    assert isinstance(artifacts, dict)  # established by _validate
    return {
        "schema": VALIDATION_SCHEMA,
        "status": "VALIDATED_ZERO_EFFECT",
        "experiment_id": R2_ID,
        "next_registered_id": NEXT_ID,
        "classification": "CLASS_C_UNCHANGED",
        "security_boundary_result": "UNKNOWN_NOT_REACHED",
        "zero_effect_validated": {
            "dispatch_count": 0,
            "fixed_op_dispatched": False,
            "panic_transition_started": False,
            "partition_writes": False,
            "memory_or_mmio_writes": False,
            "controller_writes": False,
            "device_state_write": False,
            "semantic_claim_created": False,
        },
        "artifact_descriptors": artifacts,
        "checkpoint": metadata,
    }


def _validate_r3(document: Mapping[str, object]) -> None:
    expected: Mapping[str, object] = {
        "schema": "sdm855-a90-v024-control-r3-preflight-incident-v1",
        "experiment_id": R3_INCIDENT_ID,
        "next_registered_id": R3_NEXT_ID,
        "target.model": "SM-A908N",
        "target.scope": "A90_ONLY",
        "target.soc": "SM8150",
        "claims.classification": "CLASS_C_UNCHANGED",
        "claims.fixed_op_dispatch_count": 0,
        "claims.effect_dispatched": False,
        "claims.effect_ambiguous": False,
        "claims.effect_replayed": False,
        "claims.partition_writes": False,
        "claims.memory_or_mmio_writes": False,
        "claims.controller_writes": False,
        "claims.protected_memory_read": False,
        "claims.smc": False,
        "claims.panic_before": 1,
        "claims.panic_set_0_applied": True,
        "claims.panic_after_recovery": 1,
        "claims.panic_restore_verified": True,
        "claims.semantic_claim_created": True,
        "claims.semantic_claim_retained": True,
        "claims.security_boundary_result": "UNKNOWN_NOT_REACHED",
        "claims.r3_id_consumed": True,
        "claims.same_id_reuse": False,
        "claims.temporary_sysctl_write": True,
        "claims.temporary_sysctl_write_rolled_back": True,
        "reconciliation.producer_device_state_field": "UNKNOWN",
        "reconciliation.producer_temporary_sysctl_write_field": False,
        "reconciliation.reconciled_device_state": "TEMPORARILY_CHANGED_AND_RESTORED",
        "reconciliation.reconciled_temporary_sysctl_write": True,
        "reconciliation.writefile_payload_sha256": R3_WRITEFILE_PAYLOAD_SHA256,
        "reconciliation.writefile_payload_size": R3_WRITEFILE_PAYLOAD_SIZE,
        "required_before_r4": [
            "accept only the exact V2321 writefile success payload and rc/status",
            "retain r3 as a consumed incident and never replay it",
            "reboot to obtain a new boot_id because r3 created the same-boot semantic claim",
            "freshly attest exact A90 identity, panic_on_oops=1 and control boot hash",
        ],
    }
    for dotted, value in expected.items():
        _require(document, dotted, value)

    artifacts = _get(document, "artifacts")
    if not isinstance(artifacts, dict):
        raise R2IncidentError("R3 artifact descriptors are not an object")
    for role, (digest, size) in R3_ARTIFACT_PINS.items():
        descriptor = artifacts.get(role)
        if not isinstance(descriptor, dict):
            raise R2IncidentError(f"R3 {role} descriptor is missing")
        for key, value in (("sha256", digest), ("size", size)):
            if descriptor.get(key) != value or type(descriptor.get(key)) is not type(value):
                raise R2IncidentError(f"R3 {role} descriptor is not pinned")


def validate_r3_incident(root: Path | str) -> dict[str, object]:
    """Validate the consumed R3 checkpoint and return a compact redacted summary."""

    data, metadata = _read_fixed_manifest(
        root,
        R3_MANIFEST_RELATIVE_PATH,
        R3_INCIDENT_MANIFEST_SHA256,
        R3_INCIDENT_MANIFEST_SIZE,
    )
    document = _json_object(data)
    _validate_r3(document)
    artifacts = _get(document, "artifacts")
    assert isinstance(artifacts, dict)  # established by _validate_r3
    return {
        "schema": R3_VALIDATION_SCHEMA,
        "status": "VALIDATED_CONSUMED_ZERO_OP_RESTORED_STATE",
        "experiment_id": R3_ID,
        "next_registered_id": R3_NEXT_ID,
        "classification": "CLASS_C_UNCHANGED",
        "security_boundary_result": "UNKNOWN_NOT_REACHED",
        "consumed_checkpoint": True,
        "incident_facts": {
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
        },
        "reconciliation": {
            "temporary_sysctl_write": True,
            "temporary_sysctl_write_rolled_back": True,
            "writefile_payload_sha256": R3_WRITEFILE_PAYLOAD_SHA256,
            "writefile_payload_size": R3_WRITEFILE_PAYLOAD_SIZE,
        },
        "artifact_descriptors": {
            "panic_recovery": {
                "sha256": R3_RECOVERY_DESCRIPTOR_SHA256,
                "size": R3_RECOVERY_DESCRIPTOR_SIZE,
            }
        },
        "checkpoint": metadata,
    }


def _validate_r4(document: Mapping[str, object]) -> None:
    """Validate the fixed R4 returned-result framing incident."""

    if set(document) != set(R4_TOP_LEVEL_KEYS):
        raise R2IncidentError("R4 manifest top-level keys are not exact")
    for dotted, expected in {
        "schema": "sdm855-a90-v024-control-r4-returned-incident-v1",
        "experiment_id": R4_INCIDENT_ID,
        "next_registered_id": R4_NEXT_ID,
        "status": "CONSUMED_RETURNED_RESULT_FRAMING_INCIDENT",
        "started_utc": R4_STARTED_UTC,
        "completed_utc": R4_COMPLETED_UTC,
    }.items():
        _require_r4(document, dotted, expected)
    _require_r4(document, "source", R4_SOURCE_PINS)
    _require_r4(
        document,
        "post_incident_readonly_health",
        R4_POST_INCIDENT_READONLY_HEALTH_PINS,
    )
    _require_r4(document, "target", R4_TARGET_PINS)
    _require_r4(document, "claims", R4_CLAIMS_PINS)
    _require_r4(document, "artifacts", R4_ARTIFACT_PINS)
    _require_r4(document, "panic_transition", R4_PANIC_TRANSITION_PINS)
    _require_r4(document, "fixed_op", R4_FIXED_OP_PINS)
    _require_r4(document, "parser_incident", R4_PARSER_INCIDENT_PINS)


def validate_r4_incident(root: Path | str) -> dict[str, object]:
    """Validate the consumed R4 incident and return a compact redacted summary."""

    data, metadata = _read_fixed_manifest(
        root,
        R4_MANIFEST_RELATIVE_PATH,
        R4_INCIDENT_MANIFEST_SHA256,
        R4_INCIDENT_MANIFEST_SIZE,
    )
    document = _json_object(data)
    _validate_r4(document)

    target = _get(document, "target")
    claims = _get(document, "claims")
    artifacts = _get(document, "artifacts")
    panic_transition = _get(document, "panic_transition")
    fixed_op = _get(document, "fixed_op")
    parser_incident = _get(document, "parser_incident")
    source = _get(document, "source")
    post_health = _get(document, "post_incident_readonly_health")
    assert isinstance(target, dict)  # established by _validate_r4
    assert isinstance(claims, dict)
    assert isinstance(artifacts, dict)
    assert isinstance(panic_transition, dict)
    assert isinstance(fixed_op, dict)
    assert isinstance(parser_incident, dict)
    assert isinstance(source, dict)
    assert isinstance(post_health, dict)

    return {
        "schema": R4_VALIDATION_SCHEMA,
        "status": "VALIDATED_CONSUMED_RETURNED_FRAMING_INCIDENT",
        "experiment_id": R4_ID,
        "next_registered_id": R4_NEXT_ID,
        "classification": "CLASS_C_UNCHANGED",
        "security_boundary_result": "UNKNOWN_NOT_REACHED",
        "consumed_checkpoint": True,
        "started_utc": R4_STARTED_UTC,
        "completed_utc": R4_COMPLETED_UTC,
        "source": dict(source),
        "incident_facts": {
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
        },
        "target": dict(target),
        "post_incident_readonly_health": dict(post_health),
        "panic_transition": dict(panic_transition),
        "fixed_op": dict(fixed_op),
        "parser_incident": dict(parser_incident),
        "artifact_descriptors": {
            role: dict(descriptor)
            for role, descriptor in artifacts.items()
            if isinstance(descriptor, dict)
        },
        "checkpoint": metadata,
    }
