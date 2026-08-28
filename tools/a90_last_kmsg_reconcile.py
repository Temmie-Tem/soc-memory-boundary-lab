#!/usr/bin/env python3
"""Reclassify the fixed ``last-kmsg-final`` parser incident on the host.

This producer never contacts a device and never changes the original
``last-kmsg-final`` public/private/journal/raw artifacts.  It validates those
fixed source bytes once, runs the current exact-reset parser over the retained
raw payload, and publishes a separate reconciliation receipt.  The missing
``selftest_after`` record remains explicitly unobserved; a parser correction is
not a substitute for a runtime-health observation.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Mapping, Sequence

try:
    from tools import a90_last_kmsg_capture as capture
except ModuleNotFoundError:  # Direct execution from tools/.
    import a90_last_kmsg_capture as capture  # type: ignore


REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT_NAME = "evidence/private"
MANIFEST_ROOT_NAME = "evidence/manifests"
SOURCE_EXPERIMENT_ID = capture.LAST_KMSG_EXPERIMENT_ID
SOURCE_MANIFEST_NAME = f"{SOURCE_EXPERIMENT_ID}.manifest.json"
SOURCE_METADATA_NAME = f"{SOURCE_EXPERIMENT_ID}.private.json"
SOURCE_JOURNAL_NAME = f"{SOURCE_EXPERIMENT_ID}.journal.json"
SOURCE_RAW_NAME = f"{SOURCE_EXPERIMENT_ID}.last_kmsg.raw.bin"
SOURCE_SIGNATURE_NAME = f"{SOURCE_EXPERIMENT_ID}.last_kmsg.bin"

EXPERIMENT_ID = "last-kmsg-final-reconciled"
PUBLIC_MANIFEST_NAME = f"{EXPERIMENT_ID}.manifest.json"
PRIVATE_METADATA_NAME = f"{EXPERIMENT_ID}.private.json"
PRIVATE_JOURNAL_NAME = f"{EXPERIMENT_ID}.journal.json"
PUBLIC_SCHEMA = "sdm855-a90-last-kmsg-reconciliation-public-v1"
PRIVATE_SCHEMA = "sdm855-a90-last-kmsg-reconciliation-private-v1"
JOURNAL_SCHEMA = "sdm855-a90-last-kmsg-reconciliation-journal-v1"
SELFTEST_AFTER_STATUS = "NOT_OBSERVED_DUE_TO_PRE_FIX_PARSER_STOP"
MAX_FILE_BYTES = 8 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00\Z")


class ReconcileError(ValueError):
    """A fixed source or reconciliation receipt is not exact."""


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ReconcileError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> object:
    raise ReconcileError(f"JSON constant is not finite: {value}")


def _json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=False,
                indent=2,
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise ReconcileError("reconciliation JSON is not serializable") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_symlink_components(path: Path, label: str) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    cursor = absolute
    anchor = Path(absolute.anchor or os.sep)
    while True:
        try:
            if cursor.is_symlink():
                raise ReconcileError(f"{label} component is a symlink: {cursor}")
        except OSError as exc:
            raise ReconcileError(f"cannot inspect {label}: {cursor}") from exc
        if cursor == anchor:
            break
        cursor = cursor.parent


def _path_under(path: Path, root: Path, label: str) -> Path:
    candidate = path if path.is_absolute() else root / path
    _reject_symlink_components(candidate, label)
    _reject_symlink_components(root, f"{label} root")
    resolved = candidate.resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ReconcileError(f"{label} escapes its fixed root") from exc
    return resolved


def _read_file(path: Path, root: Path, label: str) -> tuple[bytes, Path]:
    checked = _path_under(path, root, label)
    try:
        info = checked.lstat()
    except OSError as exc:
        raise ReconcileError(f"{label} cannot be inspected") from exc
    if not checked.is_file() or checked.is_symlink():
        raise ReconcileError(f"{label} is not a regular file")
    if info.st_size < 0 or info.st_size > MAX_FILE_BYTES:
        raise ReconcileError(f"{label} exceeds the bounded size")
    try:
        data = checked.read_bytes()
    except OSError as exc:
        raise ReconcileError(f"{label} cannot be read") from exc
    if len(data) != info.st_size:
        raise ReconcileError(f"{label} changed while being read")
    return data, checked


def _read_json(path: Path, root: Path, label: str) -> tuple[dict[str, object], bytes, Path]:
    data, checked = _read_file(path, root, label)
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except ReconcileError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReconcileError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ReconcileError(f"{label} root is not an object")
    return value, data, checked


def _require(value: Mapping[str, object], key: str, expected: object, label: str) -> None:
    actual = value.get(key)
    if type(actual) is not type(expected) or actual != expected:
        raise ReconcileError(f"{label} field {key!r} is not exact")


def _require_hash(value: object, expected: str, label: str) -> None:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None or value != expected:
        raise ReconcileError(f"{label} hash is not exact")


def _require_size(value: object, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise ReconcileError(f"{label} size is not exact")


def _require_utc(value: object, label: str) -> str:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise ReconcileError(f"{label} timestamp is not exact UTC")
    try:
        fmt = "%Y-%m-%dT%H:%M:%S.%f+00:00" if "." in value else "%Y-%m-%dT%H:%M:%S+00:00"
        dt.datetime.strptime(value, fmt)
    except ValueError as exc:
        raise ReconcileError(f"{label} timestamp is invalid") from exc
    return value


def _parse_boot_id(payload: bytes, label: str) -> str:
    if type(payload) is not bytes:
        raise ReconcileError(f"{label} payload is not bytes")
    if payload.endswith(b"\r\n"):
        body = payload[:-2]
    elif payload.endswith(b"\n"):
        body = payload[:-1]
    else:
        body = payload
    try:
        value = body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReconcileError(f"{label} payload is not ASCII") from exc
    if BOOT_ID_RE.fullmatch(value) is None:
        raise ReconcileError(f"{label} payload is not one exact lowercase UUID")
    return value


def _decode_b64(value: object, label: str) -> bytes:
    if type(value) is not str:
        raise ReconcileError(f"{label} base64 is not a string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ReconcileError(f"{label} base64 is malformed") from exc


def _validate_frame(
    frame: object,
    evidence_id: str,
    argv: tuple[str, ...],
    label: str,
    *,
    expected_flags: str = "0x0",
) -> bytes:
    if not isinstance(frame, Mapping):
        raise ReconcileError(f"{label} frame is not an object")
    expected_keys = {
        "argv",
        "begin",
        "end",
        "evidence_id",
        "payload_base64",
        "payload_sha256",
        "payload_size",
        "transcript_base64",
        "transcript_sha256",
        "transcript_size",
    }
    if set(frame) != expected_keys:
        raise ReconcileError(f"{label} frame fields are not exact")
    _require(frame, "evidence_id", evidence_id, label)
    _require(frame, "argv", list(argv), label)
    begin = frame.get("begin")
    end = frame.get("end")
    if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
        raise ReconcileError(f"{label} BEGIN/END records are missing")
    if set(begin) != {"cmd", "seq", "argc", "flags"}:
        raise ReconcileError(f"{label} BEGIN fields are not exact")
    if set(end) != {"cmd", "seq", "rc", "errno", "duration_ms", "flags", "status"}:
        raise ReconcileError(f"{label} END fields are not exact")
    seq = begin.get("seq")
    if type(seq) is not str or not re.fullmatch(r"[1-9][0-9]*", seq):
        raise ReconcileError(f"{label} sequence is not exact")
    for record in (begin, end):
        _require(record, "cmd", argv[0], label)
        _require(record, "seq", seq, label)
        _require(record, "flags", expected_flags, label)
    _require(begin, "argc", str(len(argv)), label)
    for key, expected in (("rc", "0"), ("errno", "0"), ("status", "ok")):
        _require(end, key, expected, label)
    duration = end.get("duration_ms")
    if type(duration) is not str or re.fullmatch(r"[0-9]+", duration) is None:
        raise ReconcileError(f"{label} duration is not exact")
    payload = _decode_b64(frame.get("payload_base64"), f"{label} payload")
    transcript = _decode_b64(frame.get("transcript_base64"), f"{label} transcript")
    _require_hash(frame.get("payload_sha256"), _sha256(payload), f"{label} payload")
    _require_size(frame.get("payload_size"), len(payload), f"{label} payload")
    _require_hash(frame.get("transcript_sha256"), _sha256(transcript), f"{label} transcript")
    _require_size(frame.get("transcript_size"), len(transcript), f"{label} transcript")
    return payload


def _validate_records(records: object, label: str) -> tuple[list[bytes], list[dict[str, object]]]:
    expected = [
        ("version_before", ("version",)),
        ("cmdline_before", ("cat", "/proc/cmdline")),
        ("boot_id_after_source", ("cat", "/proc/sys/kernel/random/boot_id")),
        ("last_kmsg", ("cat", "/proc/last_kmsg")),
    ]
    if not isinstance(records, list) or len(records) != len(expected):
        raise ReconcileError(f"{label} must contain exactly four records")
    payloads: list[bytes] = []
    summaries: list[dict[str, object]] = []
    for index, ((evidence_id, argv), frame) in enumerate(zip(expected, records)):
        payloads.append(_validate_frame(frame, evidence_id, argv, f"{label}[{index}]"))
        assert isinstance(frame, Mapping)
        summaries.append(
            {
                "evidence_id": evidence_id,
                "argv": list(argv),
                "payload_sha256": frame["payload_sha256"],
                "payload_size": frame["payload_size"],
                "transcript_sha256": frame["transcript_sha256"],
                "transcript_size": frame["transcript_size"],
            }
        )
    return payloads, summaries


def _validate_stophud(journal: Mapping[str, object]) -> dict[str, object]:
    stophud = journal.get("stophud")
    attempts = stophud.get("attempts") if isinstance(stophud, Mapping) else None
    frames = journal.get("stophud_frames")
    if (
        not isinstance(stophud, Mapping)
        or set(stophud) != {"accepted", "attempts", "busy_retries"}
        or stophud.get("accepted") is not True
        or not isinstance(attempts, list)
        or not isinstance(frames, list)
        or len(attempts) != len(frames)
        or not attempts
        or len(attempts) > 3
    ):
        raise ReconcileError("source stophud receipt is incomplete")
    busy = 0
    for index, (attempt, frame) in enumerate(zip(attempts, frames), 1):
        if not isinstance(attempt, Mapping):
            raise ReconcileError("source stophud attempt is not an object")
        if set(attempt) != {
            "attempt",
            "evidence_id",
            "payload_sha256",
            "payload_size",
            "rc",
            "status",
            "transcript_sha256",
            "transcript_size",
        }:
            raise ReconcileError("source stophud attempt fields are not exact")
        _require(attempt, "attempt", index, "source stophud attempt")
        _require(attempt, "evidence_id", f"stophud_{index}", "source stophud attempt")
        if type(attempt.get("rc")) is not int or attempt.get("status") not in {"busy", "ok"}:
            raise ReconcileError("source stophud attempt terminal is malformed")
        expected_rc = -16 if index < len(attempts) else 0
        expected_status = "busy" if index < len(attempts) else "ok"
        _require(attempt, "rc", expected_rc, "source stophud attempt")
        _require(attempt, "status", expected_status, "source stophud attempt")
        if expected_status == "busy":
            busy += 1
        payload = _validate_frame(
            frame,
            f"stophud_{index}",
            ("stophud",),
            f"source stophud frame[{index}]",
            expected_flags="0x8",
        )
        if payload not in (b"autohud: stopped", b"autohud: stopped\n"):
            raise ReconcileError("source stophud payload is not canonical")
        assert isinstance(frame, Mapping)
        for key in ("payload_sha256", "payload_size", "transcript_sha256", "transcript_size"):
            _require(attempt, key, frame[key], "source stophud attempt/frame")
    _require(stophud, "busy_retries", busy, "source stophud")
    if journal.get("stophud_attempts") != attempts or journal.get("stophud_frames") != frames:
        raise ReconcileError("source stophud projections differ")
    return {
        "accepted": True,
        "busy_retries": busy,
        "attempts": [dict(item) for item in attempts],
    }


def _target(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"bootloader", "model", "runtime", "soc"}:
        raise ReconcileError(f"{label} target fields are not exact")
    expected = {
        "bootloader": "A908NKSU5EWA3",
        "model": "SM-A908N",
        "runtime": "0.9.285",
        "soc": "SM8150",
    }
    for key, item in expected.items():
        _require(value, key, item, label)
    return dict(expected)


def _read_source(root: Path) -> dict[str, object]:
    private = root / PRIVATE_ROOT_NAME
    manifests = root / MANIFEST_ROOT_NAME
    public, public_bytes, public_path = _read_json(
        manifests / SOURCE_MANIFEST_NAME, manifests, "source public manifest"
    )
    metadata, metadata_bytes, metadata_path = _read_json(
        private / SOURCE_METADATA_NAME, private, "source metadata"
    )
    journal, journal_bytes, journal_path = _read_json(
        private / SOURCE_JOURNAL_NAME, private, "source journal"
    )
    raw_signature, raw_signature_bytes, signature_path = _read_json(
        private / SOURCE_SIGNATURE_NAME, private, "source derived signature"
    )
    captured, captured_path = _read_file(
        private / SOURCE_RAW_NAME, private, "source captured raw"
    )

    public_keys = {
        "classification",
        "completed_utc",
        "effect_dispatched",
        "effect_dispatched_count",
        "effect_replayed",
        "error",
        "expected_target",
        "experiment_id",
        "journal_filename",
        "partition_writes",
        "private_record",
        "redaction",
        "schema",
        "started_utc",
        "status",
        "target",
        "target_verified",
    }
    if set(public) != public_keys:
        raise ReconcileError("source public fields are not the fixed incident shape")
    for key, expected in {
        "schema": "sdm855-a90-last-kmsg-capture-public-v2",
        "experiment_id": SOURCE_EXPERIMENT_ID,
        "status": "INCIDENT",
        "classification": "INCIDENT",
        "target_verified": True,
        "effect_dispatched": False,
        "effect_dispatched_count": 0,
        "effect_replayed": False,
        "partition_writes": False,
        "journal_filename": SOURCE_JOURNAL_NAME,
    }.items():
        _require(public, key, expected, "source public")
    public_started = _require_utc(public.get("started_utc"), "source public started_utc")
    public_completed = _require_utc(public.get("completed_utc"), "source public completed_utc")
    if public_started != public_completed:
        raise ReconcileError("source public start/completion differ")
    _target(public.get("target"), "source public")
    expected_target = public.get("expected_target")
    if not isinstance(expected_target, Mapping):
        raise ReconcileError("source public expected target is missing")
    for key, expected in {
        "model": "SM-A908N",
        "soc": "SM8150",
        "runtime": "0.9.285",
        "bootloader": "A908NKSU5EWA3",
        "build": "v2321-usb-clean-identity-rodata",
        "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
        "version": "A90 Linux init 0.9.285",
    }.items():
        _require(expected_target, key, expected, "source public expected_target")
    private_record = public.get("private_record")
    if not isinstance(private_record, Mapping) or set(private_record) != {
        "captured_log", "filename", "journal_filename", "sha256", "size"
    }:
        raise ReconcileError("source public private_record is not exact")
    for key, expected in {
        "filename": SOURCE_SIGNATURE_NAME,
        "journal_filename": SOURCE_JOURNAL_NAME,
        "sha256": _sha256(raw_signature_bytes),
        "size": len(raw_signature_bytes),
    }.items():
        if key == "sha256":
            _require_hash(private_record.get(key), expected, "source public signature")
        elif key == "size":
            _require_size(private_record.get(key), expected, "source public signature")
        else:
            _require(private_record, key, expected, "source public signature")
    captured_record = private_record.get("captured_log")
    if not isinstance(captured_record, Mapping) or set(captured_record) != {
        "filename", "sha256", "size"
    }:
        raise ReconcileError("source public captured_log record is not exact")
    for key, expected in {
        "filename": SOURCE_RAW_NAME,
        "sha256": _sha256(captured),
        "size": len(captured),
    }.items():
        if key == "sha256":
            _require_hash(captured_record.get(key), expected, "source public captured raw")
        elif key == "size":
            _require_size(captured_record.get(key), expected, "source public captured raw")
        else:
            _require(captured_record, key, expected, "source public captured raw")

    if set(metadata) != {
        "completed_utc", "exact_reset_signature", "experiment_id", "journal_filename",
        "last_kmsg", "schema", "started_utc"
    }:
        raise ReconcileError("source metadata fields are not exact")
    for key, expected in {
        "schema": "sdm855-a90-last-kmsg-capture-private-v2",
        "experiment_id": SOURCE_EXPERIMENT_ID,
        "journal_filename": SOURCE_JOURNAL_NAME,
    }.items():
        _require(metadata, key, expected, "source metadata")
    _require(metadata, "started_utc", public_started, "source metadata")
    _require(metadata, "completed_utc", public_completed, "source metadata")
    metadata_log = metadata.get("last_kmsg")
    if not isinstance(metadata_log, Mapping) or set(metadata_log) != {
        "captured_log_filename", "captured_log_sha256", "captured_log_size", "filename",
        "markers", "sha256", "size"
    }:
        raise ReconcileError("source metadata last_kmsg fields are not exact")
    for key, expected in {
        "filename": SOURCE_SIGNATURE_NAME,
        "sha256": _sha256(raw_signature_bytes),
        "size": len(raw_signature_bytes),
        "captured_log_filename": SOURCE_RAW_NAME,
        "captured_log_sha256": _sha256(captured),
        "captured_log_size": len(captured),
    }.items():
        if key.endswith("sha256"):
            _require_hash(metadata_log.get(key), expected, "source metadata last_kmsg")
        elif key.endswith("size"):
            _require_size(metadata_log.get(key), expected, "source metadata last_kmsg")
        else:
            _require(metadata_log, key, expected, "source metadata last_kmsg")
    if metadata_log.get("markers") != public.get("markers"):
        # The fixed source public incident predates marker projection on some
        # hosts; when present, it must still be byte-identical.
        if "markers" in public and metadata_log.get("markers") != public.get("markers"):
            raise ReconcileError("source metadata/public marker projections differ")

    if set(raw_signature) != {"exact_reset_signature"}:
        raise ReconcileError("source derived signature fields are not exact")
    old_signature = raw_signature.get("exact_reset_signature")
    if not isinstance(old_signature, Mapping):
        raise ReconcileError("source derived signature is missing")
    _require(old_signature, "status", "INCIDENT", "source derived signature")
    for key, expected in {
        "debug_level_decimal": capture.EXACT_DEBUG_LEVEL_DECIMAL,
        "upload_cause": capture.EXACT_UPLOAD_CAUSE,
        "tz_reset_reason": capture.EXACT_TZ_RESET_REASON,
        "a90r_count": 0,
        "ordered_offsets_strict": False,
        "bark_last_pet_delta_seconds": None,
    }.items():
        _require(old_signature, key, expected, "source derived signature")
    old_unique = old_signature.get("uniqueness")
    if not isinstance(old_unique, Mapping):
        raise ReconcileError("source derived signature uniqueness is missing")
    for key, expected in {
        "bark": 0,
        "last_pet": 0,
        "debug_level": 1,
        "upload_cause": 1,
        "collect_upload": 1,
        "tz_reason": 1,
        "all_required_unique": False,
    }.items():
        _require(old_unique, key, expected, "source derived signature uniqueness")
    if metadata.get("exact_reset_signature") != dict(old_signature):
        raise ReconcileError("source metadata/derived signature differs")

    journal_keys = {
        "boot_id_changed", "bridge_binding", "captured_log_filename", "captured_log_sha256",
        "captured_log_size", "current_boot_id", "current_boot_id_sha256", "effect_dispatched",
        "effect_replayed", "expected_target", "experiment_id", "last_kmsg_read_once",
        "live_bridge_binding_before_last_kmsg", "post_stophud_bridge_binding", "private_record",
        "read_source", "records", "retained_sha256", "retained_size", "schema",
        "source_pre_read_boot_id", "started_utc", "status",
        "stophud", "stophud_attempts", "stophud_frames", "target", "target_verified",
        "transport_module", "transport_source", "raw_filename",
    }
    if set(journal) != journal_keys:
        raise ReconcileError("source journal fields are not the fixed incident shape")
    for key, expected in {
        "schema": "sdm855-a90-last-kmsg-capture-private-v2",
        "experiment_id": SOURCE_EXPERIMENT_ID,
        "status": "INCIDENT",
        "target_verified": True,
        "effect_dispatched": False,
        "effect_replayed": False,
        "last_kmsg_read_once": True,
        "boot_id_changed": True,
        "private_record": SOURCE_METADATA_NAME,
        "raw_filename": SOURCE_SIGNATURE_NAME,
        "captured_log_filename": SOURCE_RAW_NAME,
        "transport_module": "tools.a90_pa28_live",
        "transport_source": "tools/a90_pa28_live.py",
    }.items():
        _require(journal, key, expected, "source journal")
    journal_started = _require_utc(journal.get("started_utc"), "source journal started_utc")
    if journal_started != public_started:
        raise ReconcileError("source journal/public start times differ")
    _require(journal, "captured_log_sha256", _sha256(captured), "source journal raw")
    _require_size(journal.get("captured_log_size"), len(captured), "source journal raw")
    _require_hash(journal.get("retained_sha256"), _sha256(raw_signature_bytes), "source journal signature")
    _require_size(journal.get("retained_size"), len(raw_signature_bytes), "source journal signature")
    _target(journal.get("target"), "source journal")
    _validate_stophud(journal)
    payloads, record_summaries = _validate_records(journal.get("records"), "source journal records")
    if payloads[3] != captured:
        raise ReconcileError("source last_kmsg record differs from captured raw")
    try:
        version_text = payloads[0].decode("ascii").replace("\r\n", "\n")
        cmdline_text = payloads[1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReconcileError("source version/cmdline payload is not ASCII") from exc
    if "version: 0.9.285 build=v2321-usb-clean-identity-rodata\n" not in version_text:
        raise ReconcileError("source version record is not the fixed runtime")
    if "kernel: Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64\n" not in version_text:
        raise ReconcileError("source version record is not the fixed kernel")
    if "androidboot.em.model=SM-A908N" not in cmdline_text or "androidboot.bootloader=A908NKSU5EWA3" not in cmdline_text:
        raise ReconcileError("source cmdline record target is not exact")
    if "androidboot.debug_level=0x494d" not in cmdline_text:
        raise ReconcileError("source cmdline record is not MID")
    if "androidboot.force_upload=0x0" not in cmdline_text or "sec_debug.dump_sink=0x0" not in cmdline_text:
        raise ReconcileError("source cmdline safety flags are not exact")
    source_boot = _parse_boot_id(payloads[2], "source boot_id record")
    current_boot = journal.get("current_boot_id")
    if type(current_boot) is not str or current_boot != source_boot:
        raise ReconcileError("source current boot_id differs from its record")
    before_boot = journal.get("source_pre_read_boot_id")
    if type(before_boot) is not str or BOOT_ID_RE.fullmatch(before_boot) is None or before_boot == current_boot:
        raise ReconcileError("source boot-id change join is not exact")
    _require_hash(journal.get("current_boot_id_sha256"), _sha256(current_boot.encode("ascii")), "source current boot hash")
    read_source = journal.get("read_source")
    if not isinstance(read_source, Mapping) or set(read_source) != {
        "completed_utc", "experiment_id", "journal_sha256", "journal_size", "manifest_sha256",
        "manifest_size", "raw_sha256", "raw_size", "source_pre_read_boot_id", "source_pre_read_boot_id_sha256"
    }:
        raise ReconcileError("source read_source fields are not exact")
    _require(read_source, "experiment_id", "verification-024-read", "source read_source")
    _require(read_source, "completed_utc", read_source.get("completed_utc"), "source read_source")
    _require_utc(read_source.get("completed_utc"), "source read_source completed_utc")
    for key in ("manifest_sha256", "raw_sha256", "journal_sha256"):
        if type(read_source.get(key)) is not str or SHA256_RE.fullmatch(read_source[key]) is None:
            raise ReconcileError(f"source read_source {key} is not an exact hash")
    for key in ("manifest_size", "raw_size", "journal_size"):
        if type(read_source.get(key)) is not int or read_source[key] < 0:
            raise ReconcileError(f"source read_source {key} is not an exact size")
    _require(read_source, "source_pre_read_boot_id", before_boot, "source read_source")
    _require_hash(read_source.get("source_pre_read_boot_id_sha256"), _sha256(before_boot.encode("ascii")), "source read_source boot hash")
    if "selftest_after" in journal or "selftest_status" in journal or "selftest_after" in metadata:
        raise ReconcileError("source invents a selftest-after record")
    if journal.get("private_record") != SOURCE_METADATA_NAME:
        raise ReconcileError("source journal private record is not exact")

    recomputed = capture.parse_exact_reset_signature(captured)
    if not isinstance(recomputed, Mapping) or recomputed.get("status") != "EXACT_V024_MID_NONSECURE_WDT":
        raise ReconcileError("source raw does not reclassify to the exact watchdog signature")
    uniqueness = recomputed.get("uniqueness")
    if not isinstance(uniqueness, Mapping) or not uniqueness.get("all_required_unique"):
        raise ReconcileError("source raw watchdog markers are not all unique")
    if recomputed.get("a90r_count") != 0 or not recomputed.get("ordered_offsets_strict"):
        raise ReconcileError("source raw watchdog marker order/A90R is not exact")
    delta = recomputed.get("bark_last_pet_delta_seconds")
    if not isinstance(delta, (int, float)) or isinstance(delta, bool) or not math.isfinite(float(delta)) or not 10.0 <= float(delta) <= 12.0:
        raise ReconcileError("source raw watchdog delta is outside the fixed bound")
    return {
        "public": public,
        "public_bytes": public_bytes,
        "public_path": public_path,
        "metadata": metadata,
        "metadata_bytes": metadata_bytes,
        "metadata_path": metadata_path,
        "journal": journal,
        "journal_bytes": journal_bytes,
        "journal_path": journal_path,
        "signature": dict(old_signature),
        "signature_bytes": raw_signature_bytes,
        "signature_path": signature_path,
        "captured": captured,
        "captured_path": captured_path,
        "captured_sha256": _sha256(captured),
        "records": record_summaries,
        "read_source": dict(read_source),
        "target": _target(journal.get("target"), "source journal"),
        "stophud": {
            "accepted": True,
            "busy_retries": journal["stophud"]["busy_retries"],
            "attempts": [dict(item) for item in journal["stophud"]["attempts"]],
        },
        "started_utc": public_started,
        "completed_utc": public_completed,
        "recomputed": dict(recomputed),
    }


def _artifact(path: Path, data: bytes) -> dict[str, object]:
    return {"filename": path.name, "sha256": _sha256(data), "size": len(data)}


def _expected_outputs(source: Mapping[str, object], root: Path) -> dict[Path, bytes]:
    private = root / PRIVATE_ROOT_NAME
    manifests = root / MANIFEST_ROOT_NAME
    metadata_path = private / PRIVATE_METADATA_NAME
    journal_path = private / PRIVATE_JOURNAL_NAME
    public_path = manifests / PUBLIC_MANIFEST_NAME
    source_artifacts = {
        "public_manifest": _artifact(source["public_path"], source["public_bytes"]),
        "metadata": _artifact(source["metadata_path"], source["metadata_bytes"]),
        "journal": _artifact(source["journal_path"], source["journal_bytes"]),
        "captured_raw": _artifact(source["captured_path"], source["captured"]),
        "derived_signature": _artifact(source["signature_path"], source["signature_bytes"]),
    }
    # The public receipt keeps only the fixed read producer's safe projection;
    # its private journal/metadata retain the complete source join, including
    # the source boot UUID.  The finalizer independently revalidates that
    # private join against the immutable verification-024-read receipt.
    private_read_source = dict(source["read_source"])
    public_read_source = {
        key: value
        for key, value in source["read_source"].items()
        if key != "source_pre_read_boot_id"
    }
    journal = {
        "schema": JOURNAL_SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "source_experiment_id": SOURCE_EXPERIMENT_ID,
        "started_utc": source["started_utc"],
        "completed_utc": source["completed_utc"],
        "status": "RECONCILED",
        "original_status": "INCIDENT",
        "reclassified_status": "EXACT_V024_MID_NONSECURE_WDT",
        "parser_false_negative": True,
        "device_contact": False,
        "device_writes": False,
        "selftest_after": SELFTEST_AFTER_STATUS,
        "effect_dispatched": False,
        "effect_replayed": False,
        "partition_writes": False,
        "last_kmsg_read_once": True,
        "target": source["target"],
        "read_source": private_read_source,
        "stophud": source["stophud"],
        "records": source["records"],
        "source_artifacts": source_artifacts,
        "exact_reset_signature": source["recomputed"],
    }
    journal_bytes = _json_bytes(journal)
    metadata = {
        "schema": PRIVATE_SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "source_experiment_id": SOURCE_EXPERIMENT_ID,
        "started_utc": source["started_utc"],
        "completed_utc": source["completed_utc"],
        "original_status": "INCIDENT",
        "reclassified_status": "EXACT_V024_MID_NONSECURE_WDT",
        "parser_false_negative": True,
        "device_contact": False,
        "device_writes": False,
        "selftest_after": SELFTEST_AFTER_STATUS,
        "effect_dispatched": False,
        "effect_replayed": False,
        "partition_writes": False,
        "last_kmsg_read_once": True,
        "target": source["target"],
        "read_source": private_read_source,
        "stophud": source["stophud"],
        "records": source["records"],
        "source_artifacts": source_artifacts,
        "exact_reset_signature": source["recomputed"],
        "captured_raw": source_artifacts["captured_raw"],
        "derived_signature": source_artifacts["derived_signature"],
    }
    metadata_bytes = _json_bytes(metadata)
    private_record = {
        "metadata_filename": metadata_path.name,
        "metadata_sha256": _sha256(metadata_bytes),
        "metadata_size": len(metadata_bytes),
        "journal_filename": journal_path.name,
        "journal_sha256": _sha256(journal_bytes),
        "journal_size": len(journal_bytes),
    }
    public = {
        "schema": PUBLIC_SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "source_experiment_id": SOURCE_EXPERIMENT_ID,
        "started_utc": source["started_utc"],
        "completed_utc": source["completed_utc"],
        "original_status": "INCIDENT",
        "reclassified_status": "EXACT_V024_MID_NONSECURE_WDT",
        "parser_false_negative": True,
        "device_contact": False,
        "device_writes": False,
        "selftest_after": SELFTEST_AFTER_STATUS,
        "target": source["target"],
        "read_source": public_read_source,
        "stophud": source["stophud"],
        "records": source["records"],
        "source_artifacts": source_artifacts,
        "exact_reset_signature": source["recomputed"],
        "effect_dispatched": False,
        "effect_replayed": False,
        "partition_writes": False,
        "last_kmsg_read_once": True,
        "private_record": private_record,
    }
    public_bytes = _json_bytes(public)
    return {metadata_path: metadata_bytes, journal_path: journal_bytes, public_path: public_bytes}


def _write_or_verify(path: Path, data: bytes, mode: int) -> None:
    _reject_symlink_components(path, "reconciliation output")
    if path.exists() or path.is_symlink():
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise ReconcileError(f"reconciliation output cannot be revalidated: {path}") from exc
        if existing != data:
            raise ReconcileError(f"reconciliation output already exists with different bytes: {path}")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise ReconcileError(f"reconciliation output cannot be created: {path}") from exc
    try:
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise ReconcileError(f"reconciliation output made no progress: {path}")
            view = view[count:]
        os.fsync(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        finally:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    else:
        os.close(descriptor)
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise ReconcileError(f"reconciliation output directory cannot be synced: {path.parent}") from exc
    try:
        os.chmod(path, mode)
    except OSError as exc:
        raise ReconcileError(f"reconciliation output mode cannot be secured: {path}") from exc


def reconcile(args: argparse.Namespace | None = None, *, root: Path | None = None) -> tuple[Path, Path]:
    """Validate the fixed source and publish/read the separate reconciliation receipt."""

    if args is not None:
        if getattr(args, "execute", False) is not True:
            raise ReconcileError("reconciliation requires explicit --execute")
        if getattr(args, "experiment_id", None) != EXPERIMENT_ID:
            raise ReconcileError("reconciliation experiment ID is fixed")
        if hasattr(args, "output_root"):
            supplied = getattr(args, "output_root")
            if supplied is None or Path(supplied).resolve() != Path(REPO_ROOT).resolve():
                raise ReconcileError("reconciliation output root is fixed to REPO_ROOT")
    base = Path(REPO_ROOT if root is None else root).resolve()
    source = _read_source(base)
    private = base / PRIVATE_ROOT_NAME
    manifests = base / MANIFEST_ROOT_NAME
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifests.mkdir(parents=True, exist_ok=True, mode=0o755)
    outputs = _expected_outputs(source, base)
    for path, data in outputs.items():
        _write_or_verify(path, data, 0o600 if path.parent == private else 0o644)
    return private / PRIVATE_JOURNAL_NAME, manifests / PUBLIC_MANIFEST_NAME


produce = reconcile
reconcile_last_kmsg = reconcile


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--execute", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    journal, manifest = reconcile(build_parser().parse_args(argv))
    print(f"journal: {journal}")
    print(f"manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXPERIMENT_ID",
    "JOURNAL_SCHEMA",
    "MANIFEST_ROOT_NAME",
    "PRIVATE_ROOT_NAME",
    "PUBLIC_MANIFEST_NAME",
    "PUBLIC_SCHEMA",
    "REPO_ROOT",
    "SOURCE_EXPERIMENT_ID",
    "ReconcileError",
    "build_parser",
    "main",
    "produce",
    "reconcile",
    "reconcile_last_kmsg",
]
