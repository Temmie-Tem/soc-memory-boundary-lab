#!/usr/bin/env python3
"""Capture one fixed ``/proc/last_kmsg`` from the exact A90 native runtime.

This consumer is deliberately read-only.  It binds the operator-owned A90
bridge, arbitrates the device-side ``autohud`` holder with the shared bounded
``stophud`` command, proves the exact V2321/SM-A908N runtime, and then sends
one and only one ``cat /proc/last_kmsg`` command.  The binary log and full
transport frames remain private; the public manifest contains only bounded
hashes, sizes, statuses, and the stophud outcome.

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
from typing import Mapping, Sequence

try:
    from tools.a90_inline_remapper_mid_probe import (
        fixed_op_argv as _fixed_op_argv_full,
        parse_cmdline as _inline_parse_cmdline,
        parse_selftest as _inline_parse_selftest,
        parse_toybox_payload as _inline_parse_toybox_payload,
        parse_toybox_wc_count as _inline_parse_toybox_wc_count,
        _parse_exact_lines as _inline_parse_exact_lines,
        _parse_boot_sysfs_uevent as _inline_parse_boot_sysfs_uevent,
        _parse_stat_identity as _inline_parse_stat_identity,
        is_transport_no_value_payload as _inline_is_transport_no_value_payload,
        protocol_terminal_and_tail_valid as _inline_protocol_terminal_and_tail_valid,
        protocol_flags_for_argv as _protocol_flags_for_argv,
        protocol_expected_errno as _protocol_expected_errno,
        validate_complete_frame as _inline_validate_complete_frame,
        verify_flash_journal,
    )
    from tools.a90_acm_snapshot import (
        BEGIN_RE,
        END_RE,
        Command,
        Frame,
        json_bytes,
        parse_last_frame,
        write_new,
    )
    from tools.a90_autohud_arbitration import (
        STOPHUD_ARGV,
        STOPHUD_MAX_PAYLOAD_BYTES,
        STOPHUD_MAX_TRANSCRIPT_BYTES,
        run_stophud,
        validate_stophud_evidence_sizes,
        validate_stophud_payload,
    )
    from tools.a90_pa28_live import (
        BRIDGE_HOST,
        BRIDGE_PORT,
        BRIDGE_PROCESS_SCRIPT,
        BRIDGE_PROCESS_SCRIPT_PATH,
        BRIDGE_SERIAL_DEVICE,
        BRIDGE_SERIAL_GLOB_TOKEN,
        BRIDGE_SERIAL_ID,
        EXPECTED_BOOTLOADER,
        EXPECTED_BUILD,
        EXPECTED_KERNEL,
        EXPECTED_MODEL,
        EXPECTED_RUNTIME,
        EXPECTED_RUNTIME_BUILD,
        EXPECTED_SOC,
        EXPECTED_VERSION,
        TransportFailure,
        exchange as native_exchange,
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    from tools.a90_param_capture import parse_cmdline, validate_runtime
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_inline_remapper_mid_probe import (  # type: ignore
        fixed_op_argv as _fixed_op_argv_full,
        parse_cmdline as _inline_parse_cmdline,
        parse_selftest as _inline_parse_selftest,
        parse_toybox_payload as _inline_parse_toybox_payload,
        parse_toybox_wc_count as _inline_parse_toybox_wc_count,
        _parse_exact_lines as _inline_parse_exact_lines,
        _parse_boot_sysfs_uevent as _inline_parse_boot_sysfs_uevent,
        _parse_stat_identity as _inline_parse_stat_identity,
        is_transport_no_value_payload as _inline_is_transport_no_value_payload,
        protocol_terminal_and_tail_valid as _inline_protocol_terminal_and_tail_valid,
        protocol_flags_for_argv as _protocol_flags_for_argv,
        protocol_expected_errno as _protocol_expected_errno,
        validate_complete_frame as _inline_validate_complete_frame,
        verify_flash_journal,
    )
    from a90_acm_snapshot import (  # type: ignore
        BEGIN_RE,
        END_RE,
        Command,
        Frame,
        json_bytes,
        parse_last_frame,
        write_new,
    )
    from a90_autohud_arbitration import (  # type: ignore
        STOPHUD_ARGV,
        STOPHUD_MAX_PAYLOAD_BYTES,
        STOPHUD_MAX_TRANSCRIPT_BYTES,
        run_stophud,
        validate_stophud_evidence_sizes,
        validate_stophud_payload,
    )
    from a90_pa28_live import (  # type: ignore
        BRIDGE_HOST,
        BRIDGE_PORT,
        BRIDGE_PROCESS_SCRIPT,
        BRIDGE_PROCESS_SCRIPT_PATH,
        BRIDGE_SERIAL_DEVICE,
        BRIDGE_SERIAL_GLOB_TOKEN,
        BRIDGE_SERIAL_ID,
        EXPECTED_BOOTLOADER,
        EXPECTED_BUILD,
        EXPECTED_KERNEL,
        EXPECTED_MODEL,
        EXPECTED_RUNTIME,
        EXPECTED_RUNTIME_BUILD,
        EXPECTED_SOC,
        EXPECTED_VERSION,
        TransportFailure,
        exchange as native_exchange,
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    from a90_param_capture import parse_cmdline, validate_runtime  # type: ignore


# The local hardened transport is used for production.  Tests replace this
# narrow name with a fake frame-producing transport.
exchange = native_exchange


REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
MAX_TIMEOUT_SEC = 120.0
LAST_KMSG_REFERENCE_SIZE = 2_097_136
MAX_SOURCE_RECEIPT_BYTES = 512 * 1024
READ_SOURCE_EXPERIMENT_ID = "verification-024-read"
CONTROL_EXPERIMENT_ID = "verification-024-control-r2"
CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = (
    "56d233030e1c970b486721b21293a91a154bdc5ebe0ae811b36473457648df15"
)
CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = 4924
LAST_KMSG_EXPERIMENT_ID = "last-kmsg-final"
STOPHUD_MAX_ATTEMPTS = 3
READ_SOURCE_MANIFEST_NAME = f"{READ_SOURCE_EXPERIMENT_ID}.manifest.json"
READ_SOURCE_RAW_NAME = f"{READ_SOURCE_EXPERIMENT_ID}.json"
READ_SOURCE_JOURNAL_NAME = f"{READ_SOURCE_EXPERIMENT_ID}.journal.json"
# Exact private projection emitted by the inline probe's bounded no-value
# transport helper.  Keep this closed so extra aliases (for example
# ``partial_end`` or ``partial: {end: ...}``) cannot conceal a complete frame.
TRANSPORT_NO_VALUE_EVIDENCE_KEYS = frozenset(
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
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
READ_CANDIDATE_SHA256 = "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed"
CONTROL_CANDIDATE_SHA256 = "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247"
BOOT_PREFIX_SIZE = 60_882_944
BOOT_ATTEST_NODE = "/tmp/a90-native/verification-024-sda24"
BOOT_ATTEST_FILE = "/tmp/a90-native/verification-024-boot-prefix.bin"
# Linux allocates the block dev_t during boot.  The last-kmsg consumer must
# bind the value emitted by this run's fixed sda24 uevent instead of carrying
# a remembered major/minor pair across reboots.
BOOT_MAJOR_MIN = 1
BOOT_MAJOR_MAX = 4095
BOOT_MINOR_MIN = 0
BOOT_MINOR_MAX = 1048575
BOOT_UEVENT_STATIC_FIELDS = {
    "DEVNAME": "sda24",
    "DEVTYPE": "partition",
    "PARTN": "24",
    "PARTNAME": "boot",
}
BOOT_ATTEST_STAT_BASE = {
    "mode": "0600",
    "uid": "0",
    "gid": "0",
    "size": "0",
}
# Kept as a compatibility name for host fixtures.  It intentionally contains
# only the dev_t-independent fields; callers must add the rdev obtained from
# ``sysfs_uevent`` through ``_source_expected_stat``.
BOOT_ATTEST_STAT = dict(BOOT_ATTEST_STAT_BASE)
EXACT_DEBUG_LEVEL_DECIMAL = 1_145_654_596
EXACT_UPLOAD_CAUSE = "Non Secure Watchdog Bark"
EXACT_TZ_RESET_REASON = "TZBSP_ERR_FATAL_NON_SECURE_WDT"
EXACT_DELTA_MIN_SECONDS = 10.0
EXACT_DELTA_MAX_SECONDS = 12.0
EXACT_REFERENCE_OFFSETS = {
    "bark": 2_033_780,
    "last_pet": 2_033_888,
    "debug_level": 2_038_584,
    "upload_cause": 2_054_304,
    "collect_upload": 2_054_492,
    "tz_reason": 2_054_678,
}
LOCAL_TRANSPORT_MODULE = "tools.a90_pa28_live"
LOCAL_TRANSPORT_SOURCE = "tools/a90_pa28_live.py"
FIXED_OP_BUFFER_SIZE = 0x58
FIXED_OP_MAGIC = 0xA90C0DE5DEADBEEF
MARKERS = (
    b"Non Secure Watchdog Bark",
    b"watchdog",
    b"Watchdog",
    b"A90R",
    b"last pet",
    b"Last pet",
)

_FINITE_SECONDS = rb"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?"

# The retained source is a line-oriented kernel log.  The two source
# families below are the only accepted prefixes: printk watchdog records use
# the exact msm_watchdog task/device shape, while TZ/Upload records use the
# exact numeric-brace prefix emitted by the Samsung restart reporter.  The
# optional prefix keeps compact host fixtures useful, but an arbitrary prefix
# can never match.  Every expression is MULTILINE and consumes one complete
# line; in particular a bare CR is not a line terminator.
_PRINTK_PREFIX = (
    rb"(?:<6>\[[ \t]*[0-9]+\.[0-9]{6}\][ \t]+"
    rb"I\[0:[ \t]+swapper/0:[ \t]+0\][ \t]+"
    rb"msm_watchdog 17c10000\.qcom,wdt:[ \t]+)?"
)
_BRACE_PREFIX = rb"(?:\{[0-9]+\}[ \t]+)?"
_LINE_END = rb"(?=\r\n|\n|\Z)"

_BARK_RE = re.compile(
    rb"(?m)^" + _PRINTK_PREFIX
    + rb"(?P<marker>Watchdog bark! Now = (?P<value>" + _FINITE_SECONDS + rb"))"
    + _LINE_END
)
_LAST_PET_RE = re.compile(
    rb"(?m)^" + _PRINTK_PREFIX
    + rb"(?P<marker>Watchdog last pet at (?P<value>" + _FINITE_SECONDS + rb"))"
    + _LINE_END
)
_DEBUG_RE = re.compile(
    rb"(?m)^" + _BRACE_PREFIX
    + rb"(?P<marker>DebugLevel : (?P<value>[0-9]+), ForceUploadFlag : 0)"
    + _LINE_END
)
_DEBUG_ANY_RE = re.compile(
    rb"(?m)^" + _BRACE_PREFIX
    + rb"(?P<marker>DebugLevel : (?P<value>[^\r\n, ]+)[^\r\n]*)"
    + _LINE_END
)
_UPLOAD_RE = re.compile(
    rb"(?m)^" + _BRACE_PREFIX
    + rb"(?P<marker>UploadCause\[Non Secure Watchdog Bark\], Don't check hangcnt)"
    + _LINE_END
)
_COLLECT_UPLOAD_RE = re.compile(
    rb"(?m)^" + _BRACE_PREFIX
    + rb"(?P<marker>collect_rr_data : upload_cause = Non Secure Watchdog Bark)"
    + _LINE_END
)
_TZ_REASON_RE = re.compile(
    rb"(?m)^" + _BRACE_PREFIX
    + rb"(?P<marker>collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT)"
    + _LINE_END
)
_BARK_ANY_RE = re.compile(
    rb"(?m)^" + _PRINTK_PREFIX
    + rb"(?P<marker>Watchdog bark! Now = [^\r\n]*)" + _LINE_END
)
_LAST_PET_ANY_RE = re.compile(
    rb"(?m)^" + _PRINTK_PREFIX
    + rb"(?P<marker>Watchdog last pet at [^\r\n]*)" + _LINE_END
)
_UPLOAD_ANY_RE = re.compile(
    rb"(?m)^" + _BRACE_PREFIX
    + rb"(?P<marker>UploadCause\[Non Secure Watchdog Bark\][^\r\n]*)"
    + _LINE_END
)
_COLLECT_UPLOAD_ANY_RE = re.compile(
    rb"(?m)^" + _BRACE_PREFIX
    + rb"(?P<marker>collect_rr_data : upload_cause = Non Secure Watchdog Bark[^\r\n]*)"
    + _LINE_END
)
_TZ_REASON_ANY_RE = re.compile(
    rb"(?m)^" + _BRACE_PREFIX
    + rb"(?P<marker>collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT[^\r\n]*)"
    + _LINE_END
)
_ANY_MARKER_PATTERNS = (
    _BARK_ANY_RE,
    _LAST_PET_ANY_RE,
    _DEBUG_ANY_RE,
    _UPLOAD_ANY_RE,
    _COLLECT_UPLOAD_ANY_RE,
    _TZ_REASON_ANY_RE,
)
_MARKER_FRAGMENTS = (
    b"Watchdog bark! Now =",
    b"Watchdog last pet at",
    b"DebugLevel :",
    b"UploadCause[Non Secure Watchdog Bark]",
    b"collect_rr_data : upload_cause =",
    b"collect_rr_data : TZ OEM_RESET_REASON ::",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _signature_json_bytes(signature: Mapping[str, object]) -> bytes:
    """Serialize the signature without sorting ``ordered_offsets`` keys."""

    return (
        json.dumps(
            {"exact_reset_signature": signature},
            indent=2,
            ensure_ascii=True,
            sort_keys=False,
        )
        + "\n"
    ).encode("utf-8")


def _match_offsets(pattern: re.Pattern[bytes], payload: bytes) -> list[int]:
    return [match.start("marker") for match in pattern.finditer(payload)]


def _finite_number(raw: bytes) -> float | None:
    try:
        number = float(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number):
        return None
    return number


def _has_malformed_marker_line(payload: bytes) -> bool:
    """Reject marker text on a line outside the complete source grammar."""

    for line in re.findall(rb"[^\n]*(?:\n|\Z)", payload):
        # Keep a bare CR visible to the anchored expressions.  Only CRLF or LF
        # is removed for this full-line check.
        if line.endswith(b"\r\n"):
            body = line[:-2]
        elif line.endswith(b"\n"):
            body = line[:-1]
        else:
            body = line
        if not any(fragment in body for fragment in _MARKER_FRAGMENTS):
            continue
        if not any(pattern.fullmatch(body) for pattern in _ANY_MARKER_PATTERNS):
            return True
    return False


def parse_exact_reset_signature(payload: bytes) -> dict[str, object]:
    """Parse the exact retained V024 mid/non-secure-watchdog signature.

    The parser is intentionally independent of line prefixes and accepts a
    synthetic/padded fixture, while requiring every exact field once and in
    the byte order observed in the retained reference log.
    """

    if not isinstance(payload, bytes):
        raise TypeError("last_kmsg payload must be bytes")

    bark_matches = list(_BARK_RE.finditer(payload))
    last_pet_matches = list(_LAST_PET_RE.finditer(payload))
    debug_matches = list(_DEBUG_RE.finditer(payload))
    debug_any_matches = list(_DEBUG_ANY_RE.finditer(payload))
    upload_offsets = _match_offsets(_UPLOAD_RE, payload)
    collect_offsets = _match_offsets(_COLLECT_UPLOAD_RE, payload)
    tz_offsets = _match_offsets(_TZ_REASON_RE, payload)
    upload_any = list(_UPLOAD_ANY_RE.finditer(payload))
    collect_any = list(_COLLECT_UPLOAD_ANY_RE.finditer(payload))
    tz_any = list(_TZ_REASON_ANY_RE.finditer(payload))
    a90r_count = payload.count(b"A90R")

    # A non-finite timestamp must be an incident, not an UNKNOWN empty-log
    # classification.  Count the anchored complete-line forms separately so
    # NaN/inf, malformed values, and invalid prefixes remain visible.
    bark_any = list(_BARK_ANY_RE.finditer(payload))
    last_pet_any = list(_LAST_PET_ANY_RE.finditer(payload))
    bark_value = (
        _finite_number(bark_matches[0].group("value"))
        if len(bark_matches) == 1
        else None
    )
    last_pet_value = (
        _finite_number(last_pet_matches[0].group("value"))
        if len(last_pet_matches) == 1
        else None
    )
    debug_value: int | None = None
    if len(debug_matches) == 1:
        try:
            debug_value = int(debug_matches[0].group("value"), 10)
        except ValueError:
            debug_value = None
    if debug_value is None and len(debug_any_matches) == 1:
        try:
            debug_value = int(debug_any_matches[0].group("value"), 10)
        except ValueError:
            pass

    offsets: dict[str, int | None] = {
        "bark": bark_matches[0].start("marker") if len(bark_matches) == 1 else None,
        "last_pet": last_pet_matches[0].start("marker")
        if len(last_pet_matches) == 1
        else None,
        "debug_level": debug_matches[0].start("marker")
        if len(debug_matches) == 1
        else (
            debug_any_matches[0].start("marker") if len(debug_any_matches) == 1 else None
        ),
        "upload_cause": upload_offsets[0] if len(upload_offsets) == 1 else None,
        "collect_upload": collect_offsets[0]
        if len(collect_offsets) == 1
        else None,
        "tz_reason": tz_offsets[0] if len(tz_offsets) == 1 else None,
    }
    counts = {
        "bark": len(bark_any),
        "last_pet": len(last_pet_any),
        "debug_level": len(debug_any_matches),
        "upload_cause": len(upload_offsets),
        "collect_upload": len(collect_offsets),
        "tz_reason": len(tz_offsets),
    }
    values = tuple(value for value in offsets.values() if isinstance(value, int))
    strict_order = (
        len(values) == len(offsets)
        and list(values) == sorted(set(values))
    )
    delta = (
        bark_value - last_pet_value
        if bark_value is not None and last_pet_value is not None
        else None
    )
    delta_ok = (
        delta is not None
        and math.isfinite(delta)
        and EXACT_DELTA_MIN_SECONDS <= delta <= EXACT_DELTA_MAX_SECONDS
    )
    required_present = all(counts.values())
    all_unique = all(count == 1 for count in counts.values())
    exact_debug = debug_value == EXACT_DEBUG_LEVEL_DECIMAL
    finite_fields = len(bark_any) == len(bark_matches) and len(last_pet_any) == len(
        last_pet_matches
    )
    malformed_marker_line = _has_malformed_marker_line(payload)
    any_evidence = bool(
        bark_any
        or last_pet_any
        or debug_any_matches
        or upload_any
        or collect_any
        or tz_any
        or malformed_marker_line
        or a90r_count
    )
    exact = (
        required_present
        and all_unique
        and finite_fields
        and len(debug_matches) == 1
        and exact_debug
        and a90r_count == 0
        and strict_order
        and delta_ok
        and not malformed_marker_line
    )
    status = (
        "EXACT_V024_MID_NONSECURE_WDT"
        if exact
        else ("INCIDENT" if any_evidence else "UNKNOWN")
    )
    exact_strings = {
        "debug_level": (
            debug_matches[0].group("marker").decode("ascii", errors="strict")
            if len(debug_matches) == 1
            else "DebugLevel : 1145654596"
        ),
        "bark": (
            bark_matches[0].group("marker").decode("ascii", errors="strict")
            if len(bark_matches) == 1
            else "Watchdog bark! Now = <finite>"
        ),
        "last_pet": (
            last_pet_matches[0].group("marker").decode("ascii", errors="strict")
            if len(last_pet_matches) == 1
            else "Watchdog last pet at <finite>"
        ),
        "upload_cause": "UploadCause[Non Secure Watchdog Bark]",
        "collect_upload": "collect_rr_data : upload_cause = Non Secure Watchdog Bark",
        "tz_reason": "collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT",
    }
    signature: dict[str, object] = {
        "status": status,
        "debug_level_decimal": debug_value,
        "upload_cause": EXACT_UPLOAD_CAUSE,
        "tz_reset_reason": EXACT_TZ_RESET_REASON,
        "a90r_count": a90r_count,
        "exact_strings": exact_strings,
        "expected_exact_strings": {
            "debug_level": "DebugLevel : 1145654596",
            "bark": "Watchdog bark! Now = <finite>",
            "last_pet": "Watchdog last pet at <finite>",
            "upload_cause": "UploadCause[Non Secure Watchdog Bark]",
            "collect_upload": "collect_rr_data : upload_cause = Non Secure Watchdog Bark",
            "tz_reason": "collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT",
        },
        "ordered_offsets": offsets,
        "ordered_byte_offsets": dict(offsets),
        "uniqueness": {
            **counts,
            "all_required_unique": all_unique,
        },
        "ordered_offsets_strict": strict_order,
        "reference_offsets": dict(EXACT_REFERENCE_OFFSETS),
        "reference_offsets_match": offsets == EXACT_REFERENCE_OFFSETS,
        "payload_size": len(payload),
        "reference_size": LAST_KMSG_REFERENCE_SIZE,
        "bark_now_seconds": bark_value,
        "last_pet_seconds": last_pet_value,
        "bark_last_pet_delta_seconds": delta,
        "times": {
            "bark_now": bark_value,
            "last_pet": last_pet_value,
            "delta": delta,
        },
        "delta_bound_seconds": {
            "min": EXACT_DELTA_MIN_SECONDS,
            "max": EXACT_DELTA_MAX_SECONDS,
        },
    }
    return signature


# Stable aliases make the parser discoverable to host-only reviewers/tests.
exact_reset_signature = parse_exact_reset_signature
validate_reset_signature = parse_exact_reset_signature


def marker_summary(payload: bytes) -> dict[str, object]:
    counts = {marker.decode("ascii"): payload.count(marker) for marker in MARKERS}
    exact = parse_exact_reset_signature(payload)
    return {
        "counts": counts,
        "non_secure_watchdog_bark_present": counts["Non Secure Watchdog Bark"] > 0,
        "a90r_result_present": counts["A90R"] > 0,
        "exact_reset_signature": exact,
    }


def _frame_record(command: Command, frame: Frame) -> dict[str, object]:
    begin = getattr(frame, "begin", {})
    end = getattr(frame, "end", {})
    payload = getattr(frame, "payload", b"")
    transcript = getattr(frame, "transcript", b"")
    return {
        "evidence_id": command.evidence_id,
        "argv": list(command.argv),
        "begin": dict(begin) if isinstance(begin, Mapping) else {},
        "end": dict(end) if isinstance(end, Mapping) else {},
        "payload_base64": base64.b64encode(payload).decode("ascii") if isinstance(payload, bytes) else "",
        "payload_sha256": sha256(payload) if isinstance(payload, bytes) else None,
        "payload_size": len(payload) if isinstance(payload, bytes) else None,
        "transcript_base64": base64.b64encode(transcript).decode("ascii") if isinstance(transcript, bytes) else "",
        "transcript_sha256": sha256(transcript) if isinstance(transcript, bytes) else None,
        "transcript_size": len(transcript) if isinstance(transcript, bytes) else None,
    }


def _partial_record(command: Command, exc: BaseException) -> dict[str, object]:
    """Retain bounded partial transport evidence without claiming completion."""

    partial = getattr(exc, "partial", None)
    payload = getattr(exc, "partial_payload", None)
    transcript = getattr(exc, "partial_transcript", None)
    begin = getattr(exc, "partial_begin", None)
    end = getattr(exc, "partial_end", None)
    if partial is not None:
        payload = getattr(partial, "payload", payload)
        transcript = getattr(partial, "transcript", transcript)
        begin = getattr(partial, "begin", begin)
        end = getattr(partial, "end", end)
    return {
        "evidence_id": command.evidence_id,
        "argv": list(command.argv),
        "transport_error_type": type(exc).__name__,
        "transport_error": str(exc),
        "partial_payload_base64": (
            base64.b64encode(payload).decode("ascii")
            if isinstance(payload, bytes)
            else None
        ),
        "partial_payload_sha256": sha256(payload) if isinstance(payload, bytes) else None,
        "partial_payload_size": len(payload) if isinstance(payload, bytes) else None,
        "partial_transcript_base64": (
            base64.b64encode(transcript).decode("ascii")
            if isinstance(transcript, bytes)
            else None
        ),
        "partial_transcript_sha256": (
            sha256(transcript) if isinstance(transcript, bytes) else None
        ),
        "partial_transcript_size": (
            len(transcript) if isinstance(transcript, bytes) else None
        ),
        "partial_begin": dict(begin) if isinstance(begin, Mapping) else None,
        "partial_end": dict(end) if isinstance(end, Mapping) else None,
    }


def _bridge_bindings_match(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Compare identity-bearing bridge fields, ignoring validation time."""

    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def _write_journal(path: Path, value: object) -> None:
    """Durably update the private incident journal using one fixed path."""

    data = json_bytes(value)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(f"private journal temporary already exists: {temporary}")
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _reject_symlink_components(path: Path, label: str) -> None:
    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(cursor.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise ValueError(f"{label} component is a symlink: {cursor}")
        if cursor == anchor:
            break
        cursor = cursor.parent


def _create_initial_journal(path: Path, value: object) -> None:
    """Create the first journal inode with an exclusive final-path claim."""

    data = json_bytes(value)
    _reject_symlink_components(path.parent, "initial private journal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    # Do not remove a partially written final inode on failure: its presence
    # is the durable no-replay ownership claim for this fixed experiment.
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        # The fd is closed by fdopen on the normal write path.  The final
        # inode intentionally remains as an ownership claim.
        raise


def _reject_existing(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"output already exists: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(f"output temporary already exists: {temporary}")


def _publish_incident_manifest(
    path: Path,
    *,
    experiment_id: str,
    started: str,
    status: str,
    error: object,
    journal_path: Path,
    expected_target: Mapping[str, object],
    target_verified: bool = False,
    target: Mapping[str, object] | None = None,
    effect_dispatched: bool = False,
    private_record: Mapping[str, object] | None = None,
) -> None:
    """Publish redacted incident evidence without raw/cmdline/serial data."""

    value: dict[str, object] = {
        "schema": "sdm855-a90-last-kmsg-capture-public-v2",
        "experiment_id": experiment_id,
        "started_utc": started,
        "completed_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "status": status,
        "classification": status,
        "expected_target": dict(expected_target),
        "target": dict(target) if target_verified and target is not None else None,
        "target_verified": bool(target_verified),
        "journal_filename": journal_path.name,
        "effect_dispatched": bool(effect_dispatched),
        "effect_dispatched_count": 1 if effect_dispatched else 0,
        "effect_replayed": False,
        "partition_writes": False,
        "error": str(error),
        "redaction": {
            "serial_identity": "omitted",
            "cmdline": "omitted",
            "raw_transcript": "omitted",
        },
    }
    if private_record is not None:
        value["private_record"] = dict(private_record)
    write_new(path, json_bytes(value), 0o644)


def _validate_output_root(root: Path) -> Path:
    lexical = root if root.is_absolute() else Path.cwd() / root
    cursor = lexical
    anchor = Path(cursor.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise ValueError(f"evidence path component must not be a symlink: {cursor}")
        if cursor == anchor:
            break
        cursor = cursor.parent
    resolved = lexical.resolve()
    private_root = resolved / "evidence" / "private"
    manifest_root = resolved / "evidence" / "manifests"
    for item in (resolved, resolved / "evidence", private_root, manifest_root):
        if item.is_symlink():
            raise ValueError(f"evidence path component must not be a symlink: {item}")
    return resolved


def _fixed_output_root(args: argparse.Namespace) -> Path:
    """Resolve only the repository-owned evidence root.

    ``--output-root`` is intentionally absent from the production parser, but
    a Namespace caller can still inject an attribute.  Tests may patch
    ``REPO_ROOT`` to an isolated fixture root; every other value is rejected
    before the fixed read source is opened or the bridge is contacted.
    """

    _validate_output_root(REPO_ROOT)
    expected = REPO_ROOT.resolve()
    # Validate the fixed namespace even when no injected selector exists;
    # otherwise a pre-existing symlinked evidence directory could redirect
    # the first journal write before bridge validation.
    _validate_output_root(expected)
    if hasattr(args, "output_root"):
        supplied = getattr(args, "output_root")
        if supplied is None:
            raise ValueError("output root selector is disabled; root is fixed to REPO_ROOT")
        try:
            supplied_path = Path(supplied)
            _validate_output_root(supplied_path)
            if supplied_path.resolve() != expected:
                raise ValueError("output root selector is disabled; root is fixed to REPO_ROOT")
        except ValueError:
            raise
        except (TypeError, OSError) as exc:
            raise ValueError("output root selector is disabled; root is fixed to REPO_ROOT") from exc
    return expected


def _stable_source_bytes(path: Path, root: Path, label: str) -> bytes:
    """Read one fixed source receipt without following any path component."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    root_lexical = root if root.is_absolute() else Path.cwd() / root
    try:
        lexical.relative_to(root_lexical)
    except ValueError as exc:
        raise ValueError(f"{label} is outside the fixed evidence root") from exc
    cursor = lexical
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise ValueError(f"{label} component is a symlink: {cursor}")
        if cursor == anchor:
            break
        cursor = cursor.parent
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lexical, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened: {lexical}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file")
        if before.st_size < 0 or before.st_size > MAX_SOURCE_RECEIPT_BYTES:
            raise ValueError(f"{label} exceeds bounded size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_SOURCE_RECEIPT_BYTES - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SOURCE_RECEIPT_BYTES:
                raise ValueError(f"{label} exceeds bounded size")
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
            raise ValueError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _source_json(path: Path, root: Path, label: str) -> tuple[dict[str, object], bytes]:
    data = _stable_source_bytes(path, root, label)
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} root is not an object")
    return value, data


def _strict_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _parse_boot_id(payload: bytes, label: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not ASCII") from exc
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if not value or value != value.strip() or "\n" in value or "\r" in value or BOOT_ID_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not one lowercase boot UUID")
    return value


def _parse_source_canonical_devnum(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> str:
    """Validate one exact unsigned decimal Linux device-number field."""

    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise ValueError(f"{label} is not canonical unsigned decimal")
    number = int(value, 10)
    if not minimum <= number <= maximum:
        raise ValueError(f"{label} is outside the bounded device-number range")
    return value


def _validate_source_uevent_mapping(value: object, label: str) -> dict[str, str]:
    """Validate the fixed sda24 identity while keeping its dev_t dynamic."""

    if not isinstance(value, Mapping):
        raise ValueError(f"{label} uevent mapping is missing")
    if set(value) != {"MAJOR", "MINOR", *BOOT_UEVENT_STATIC_FIELDS}:
        raise ValueError(f"{label} uevent fields are not exact")
    major = _parse_source_canonical_devnum(
        value.get("MAJOR"),
        f"{label} MAJOR",
        BOOT_MAJOR_MIN,
        BOOT_MAJOR_MAX,
    )
    minor = _parse_source_canonical_devnum(
        value.get("MINOR"),
        f"{label} MINOR",
        BOOT_MINOR_MIN,
        BOOT_MINOR_MAX,
    )
    for key, expected in BOOT_UEVENT_STATIC_FIELDS.items():
        if value.get(key) != expected:
            raise ValueError(f"{label} {key} is not exact")
    return {
        "MAJOR": major,
        "MINOR": minor,
        **BOOT_UEVENT_STATIC_FIELDS,
    }


def _parse_source_uevent_payload(payload: bytes, label: str) -> dict[str, str]:
    """Decode a retained uevent with the producer's strict source grammar."""

    try:
        parsed = _inline_parse_boot_sysfs_uevent(payload)
    except BaseException as exc:
        raise ValueError(f"{label} uevent payload is malformed") from exc
    try:
        return _validate_source_uevent_mapping(parsed, label)
    except BaseException as exc:
        raise ValueError(f"{label} uevent payload differs from fixed sda24") from exc


def _source_expected_stat(uevent: Mapping[str, str]) -> dict[str, str]:
    """Return the exact stat projection bound to one validated uevent."""

    validated = _validate_source_uevent_mapping(uevent, "source")
    return {
        **BOOT_ATTEST_STAT_BASE,
        "rdev": f"{validated['MAJOR']}:{validated['MINOR']}",
    }


def _validate_source_mknod_argv(value: object, label: str) -> tuple[str, ...]:
    """Validate mknod syntax; its dev_t is cross-bound to the uevent later."""

    if not isinstance(value, (list, tuple)) or len(value) != 4:
        raise ValueError(f"{label} mknod argv is not exact")
    argv = tuple(value)
    if argv[:2] != ("mknodb", BOOT_ATTEST_NODE):
        raise ValueError(f"{label} mknod path/command is not exact")
    _parse_source_canonical_devnum(
        argv[2], f"{label} mknod major", BOOT_MAJOR_MIN, BOOT_MAJOR_MAX
    )
    _parse_source_canonical_devnum(
        argv[3], f"{label} mknod minor", BOOT_MINOR_MIN, BOOT_MINOR_MAX
    )
    return argv


def _fixed_attestation(
    value: object,
    expected_hash: str,
    label: str,
    *,
    require_paths: bool = True,
) -> Mapping[str, object]:
    """Require the complete sda24 prefix proof, including dynamic dev_t."""

    if not isinstance(value, Mapping):
        raise ValueError(f"{label} current boot attestation is missing")
    uevent = _validate_source_uevent_mapping(
        value.get("sysfs_uevent"), f"{label} current boot"
    )
    expected = {
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
            {"attest_node": BOOT_ATTEST_NODE, "attest_file": BOOT_ATTEST_FILE}
        )
    for key, expected_value in expected.items():
        if type(value.get(key)) is not type(expected_value) or value.get(key) != expected_value:
            raise ValueError(f"{label} current boot attestation {key!r} is not exact")
    stat_value = value.get("stat")
    if not isinstance(stat_value, Mapping):
        raise ValueError(f"{label} current boot attestation stat is missing")
    expected_stat = _source_expected_stat(uevent)
    for key, expected_value in expected_stat.items():
        if stat_value.get(key) != expected_value:
            raise ValueError(f"{label} current boot attestation stat is not exact")
    if require_paths and ("cleanup_error" not in value or value.get("cleanup_error") is not None):
        raise ValueError(f"{label} current boot attestation cleanup has an error")
    if not require_paths and "cleanup_error" in value and value.get("cleanup_error") is not None:
        raise ValueError(f"{label} current boot attestation cleanup has an error")
    return value


def _fixed_op_argv() -> list[str]:
    # The shell body is not caller-controlled, but retaining its exact prefix
    # and operation node makes a source receipt unable to claim another op.
    return [
        "run",
        "/bin/busybox",
        "sh",
        "-c",
    ]


def _fixed_op_buffer_hash() -> str:
    buffer = bytearray(FIXED_OP_BUFFER_SIZE)
    struct.pack_into("<Q", buffer, 0, FIXED_OP_MAGIC)
    buffer[8] = 4
    return sha256(bytes(buffer))


def _validate_source_target(target: object, label: str) -> None:
    if not isinstance(target, Mapping):
        raise ValueError(f"{label} target is missing")
    expected = {
        "model": EXPECTED_MODEL,
        "soc": EXPECTED_SOC,
        "soc_id": "339",
        "runtime_version": EXPECTED_RUNTIME,
        "runtime_build": EXPECTED_RUNTIME_BUILD,
        "kernel": EXPECTED_KERNEL,
        "bootloader": EXPECTED_BOOTLOADER,
        "debug_level": "0x494d",
        "force_upload": "0",
        "dump_sink": "0",
    }
    for key, expected_value in expected.items():
        if type(target.get(key)) is not type(expected_value) or target.get(key) != expected_value:
            raise ValueError(f"{label} target field {key!r} is not exact")


def _validate_source_fixed_op(
    value: object, label: str, *, terminal: bool = False
) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} fixed_op is missing")
    expected_keys = {
        "op",
        "args",
        "buffer_size",
        "buffer_sha256",
    }
    if terminal:
        expected_keys.update({"rc", "status", "value"})
    if set(value) != expected_keys:
        raise ValueError(f"{label} fixed_op fields are not exact")
    expected = {
        "op": 4,
        "args": [],
        "buffer_size": FIXED_OP_BUFFER_SIZE,
        "buffer_sha256": _fixed_op_buffer_hash(),
    }
    if terminal:
        expected.update({"rc": None, "status": None, "value": None})
    for key, expected_value in expected.items():
        if type(value.get(key)) is not type(expected_value) or value.get(key) != expected_value:
            raise ValueError(f"{label} fixed_op field {key!r} is not exact")


def _validate_source_transition(value: object, label: str) -> None:
    expected = {
        "before": 1,
        "zero_write_attempted": True,
        "zero_set": True,
        "zero_verified": True,
        "restore_write_attempted": False,
        "restored": False,
        "restore_deferred": True,
        "proof_frame_ids": ["panic_before", "panic_set_0", "panic_zero_verify"],
    }
    if value != expected:
        raise ValueError(f"{label} panic transition proof is not exact")


def _validate_source_control_binding(value: object, label: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} control receipt binding is missing")
    expected = {
        "mode": "control",
        "candidate_sha256": CONTROL_CANDIDATE_SHA256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "value": "0x000000000000c071",
        "target_dmid": "SM-A908N/SM8150",
        "predecessor_capsule_sha256": CONTROL_R2_PREDECESSOR_CAPSULE_SHA256,
        "predecessor_capsule_size": CONTROL_R2_PREDECESSOR_CAPSULE_SIZE,
    }
    for key, expected_value in expected.items():
        if type(value.get(key)) is not type(expected_value) or value.get(key) != expected_value:
            raise ValueError(f"{label} control binding field {key!r} is not exact")
    experiment_id = value.get("experiment_id")
    if experiment_id != CONTROL_EXPERIMENT_ID:
        raise ValueError(f"{label} control binding experiment_id is not exact")
    for key in ("manifest_sha256", "raw_sha256", "journal_sha256", "boot_id_before_read_sha256"):
        digest = value.get(key)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"{label} control binding {key!r} is malformed")
    for key in ("manifest_size", "raw_size", "journal_size"):
        size = value.get(key)
        if type(size) is not int or size <= 0 or size > MAX_SOURCE_RECEIPT_BYTES:
            raise ValueError(f"{label} control binding {key!r} is malformed")
    completion = value.get("completed_utc")
    if not isinstance(completion, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00", completion) is None:
        raise ValueError(f"{label} control binding completion is malformed")
    _fixed_attestation(
        value.get("current_boot_attestation"),
        CONTROL_CANDIDATE_SHA256,
        f"{label} control current boot",
        require_paths=False,
    )
    measurement = value.get("fixed_op_measurement")
    if not isinstance(measurement, Mapping):
        raise ValueError(f"{label} control fixed-op measurement is missing")
    if measurement.get("argv") != list(_fixed_op_argv_full()):
        raise ValueError(f"{label} control fixed-op measurement argv is not exact")
    for key, expected_value in {
        "op": 4,
        "args": [],
        "buffer_size": FIXED_OP_BUFFER_SIZE,
        "buffer_sha256": _fixed_op_buffer_hash(),
        "magic": "0xa90c0de5deadbeef",
        "rc": 0,
        "status": "ok",
        "value": "0x000000000000c071",
        "a90r_record": "A90Rc071",
    }.items():
        if measurement.get(key) != expected_value:
            raise ValueError(f"{label} control fixed-op measurement {key!r} is not exact")


def _validate_source_partial_begin_binding(
    value: Mapping[str, object],
    transcript: bytes | None,
    argv: list[str],
    label: str,
) -> None:
    """Bind optional source BEGIN metadata to its retained transcript."""

    begin = value.get("begin")
    if transcript is None:
        if begin is not None:
            raise ValueError(f"{label} begin is present without a transcript")
        return
    begins = list(BEGIN_RE.finditer(transcript))
    ends = list(END_RE.finditer(transcript))
    if transcript.count(b"A90P1 BEGIN") != len(begins):
        raise ValueError(f"{label} transcript has malformed BEGIN framing")
    if transcript.count(b"A90P1 END") != len(ends):
        raise ValueError(f"{label} transcript has malformed END framing")
    if ends:
        raise ValueError(f"{label} transcript contains a complete END frame")
    if not begins:
        raise ValueError(
            f"{label} transcript lacks the fixed-op BEGIN exchange boundary"
        )
    if len(begins) != 1 or not isinstance(begin, Mapping):
        raise ValueError(f"{label} transcript BEGIN count/binding is not exact")
    try:
        fields = begins[0].group("fields").decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} BEGIN fields are not ASCII") from exc
    parsed: dict[str, str] = {}
    for token in fields.split():
        if "=" not in token:
            raise ValueError(f"{label} BEGIN field token is malformed")
        key, item = token.split("=", 1)
        if not key or not item or key in parsed:
            raise ValueError(f"{label} BEGIN field set is malformed")
        parsed[key] = item
    # A retained no-value BEGIN is only valid for the canonical five-field
    # ``run`` dispatch record.  In particular, accepting a shortened
    # ``cmd=run seq=...`` summary would allow an old/foreign protocol frame
    # to be replayed as a fresh causal source.
    if set(parsed) != {"cmd", "seq", "argc", "flags"}:
        raise ValueError(f"{label} BEGIN field set is not exact")
    sequence = parsed.get("seq")
    if (
        parsed.get("cmd") != argv[0]
        or not isinstance(sequence, str)
        or re.fullmatch(r"[0-9]+", sequence) is None
        or (len(sequence) > 1 and sequence.startswith("0"))
        or parsed.get("argc") != "5"
        or parsed.get("flags") != _protocol_flags_for_argv(argv)
    ):
        raise ValueError(f"{label} BEGIN command/sequence/argc/flags is not exact")
    if dict(begin) != parsed:
        raise ValueError(f"{label} begin metadata differs from transcript")


def _validate_source_partial_payload_relation(
    payload: bytes | None, transcript: bytes | None, label: str
) -> None:
    """Match the producer's ``_partial_from_transcript`` payload relation."""

    if transcript is None:
        if payload is not None:
            raise ValueError(f"{label} payload is present without a transcript")
        return
    begins = list(BEGIN_RE.finditer(transcript))
    if not begins:
        if payload is not None:
            raise ValueError(f"{label} payload is present without a BEGIN")
        return
    if len(begins) != 1 or payload is None:
        raise ValueError(f"{label} payload/BEGIN relation is incomplete")
    expected = transcript[begins[0].end() :]
    if payload != expected:
        raise ValueError(f"{label} payload does not equal retained post-BEGIN bytes")


def _validate_source_flash(value: object, label: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} flash journal binding is missing")
    expected = {
        "profile": "read",
        "image_sha256": READ_CANDIDATE_SHA256,
        "readback_sha256": READ_CANDIDATE_SHA256,
        "predecessor_sha256": CONTROL_CANDIDATE_SHA256,
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise ValueError(f"{label} flash journal field {key!r} is not exact")
    path = value.get("path")
    digest = value.get("sha256")
    size = value.get("size")
    if not isinstance(path, str) or not path or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None or type(size) is not int or size <= 0:
        raise ValueError(f"{label} flash journal hash binding is malformed")


def _validate_source_semantic_claim(
    root: Path,
    public: Mapping[str, object],
    raw: Mapping[str, object],
    journal: Mapping[str, object],
    *,
    mode: str,
    candidate_sha256: str,
    label: str,
) -> None:
    boot_id = raw.get("boot_id_before_read")
    if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
        raise ValueError(f"{label} semantic claim boot_id is malformed")
    key_material = (
        f"verification-024-inline-op\0{mode}\0{candidate_sha256}\0"
        f"{BOOT_PREFIX_SIZE}\0{boot_id}"
    ).encode("ascii")
    key_sha256 = sha256(key_material)
    filename = f"verification-024-inline-op-{key_sha256}.claim.json"
    claim_path = root / "evidence" / "private" / filename
    claim_hash = raw.get("semantic_claim_sha256")
    claim_size = raw.get("semantic_claim_size")
    if raw.get("semantic_claim_path") != str(claim_path) or not isinstance(claim_hash, str) or re.fullmatch(r"[0-9a-f]{64}", claim_hash) is None or type(claim_size) is not int or claim_size <= 0 or claim_size > MAX_SOURCE_RECEIPT_BYTES:
        raise ValueError(f"{label} semantic claim binding is malformed")
    for owner in (raw, journal):
        if owner.get("semantic_claim_path") != str(claim_path) or owner.get("semantic_claim_sha256") != claim_hash or owner.get("semantic_claim_size") != claim_size or owner.get("semantic_claim_key_sha256") != key_sha256 or owner.get("semantic_claimed") is not True:
            raise ValueError(f"{label} semantic claim is not cross-bound")
    public_claim = public.get("semantic_claim")
    if not isinstance(public_claim, Mapping) or public_claim.get("filename") != filename or public_claim.get("sha256") != claim_hash or public_claim.get("size") != claim_size or public_claim.get("key_sha256") != key_sha256:
        raise ValueError(f"{label} public semantic claim is not exact")
    claim, claim_data = _source_json(claim_path, root / "evidence" / "private", f"{label} semantic claim")
    if sha256(claim_data) != claim_hash or len(claim_data) != claim_size:
        raise ValueError(f"{label} semantic claim hash/size differs")
    for key, expected in {
        "schema": "sdm855-a90-inline-op-semantic-claim-v1",
        "mode": mode,
        "candidate_sha256": candidate_sha256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "boot_id": boot_id,
        "boot_id_sha256": sha256(boot_id.encode("ascii")),
        "key_sha256": key_sha256,
        "claimed_by_experiment_id": raw.get("experiment_id"),
        "effect_replayed": False,
    }.items():
        if claim.get(key) != expected:
            raise ValueError(f"{label} semantic claim field {key!r} is not exact")


def _validate_source_read(
    root: Path, source_experiment_id: str = READ_SOURCE_EXPERIMENT_ID
) -> dict[str, object]:
    """Load and validate the one fixed no-value read receipt used as source."""

    if source_experiment_id != READ_SOURCE_EXPERIMENT_ID:
        raise ValueError("read source experiment ID is not the fixed V024 source")
    source_manifest_name = f"{source_experiment_id}.manifest.json"
    source_raw_name = f"{source_experiment_id}.json"
    source_journal_name = f"{source_experiment_id}.journal.json"

    manifest_path = root / "evidence" / "manifests" / source_manifest_name
    raw_path = root / "evidence" / "private" / source_raw_name
    journal_path = root / "evidence" / "private" / source_journal_name
    manifest, manifest_bytes = _source_json(
        manifest_path, root / "evidence" / "manifests", "read source manifest"
    )
    raw, raw_bytes = _source_json(raw_path, root / "evidence" / "private", "read source raw")
    journal, journal_bytes = _source_json(
        journal_path, root / "evidence" / "private", "read source journal"
    )
    if manifest.get("schema") != "sdm855-a90-inline-remapper-mid-public-v1" or manifest.get("experiment_id") != source_experiment_id or manifest.get("mode") != "read":
        raise ValueError("read source manifest is not the fixed V024 read receipt")
    for key, expected in {
        "candidate_sha256": READ_CANDIDATE_SHA256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "target_verified": True,
        "target_evaluation": "VERIFIED",
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "runtime": "0.9.285",
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
        "flash_profile": "read",
        "flash_image_sha256": READ_CANDIDATE_SHA256,
        "flash_readback_sha256": READ_CANDIDATE_SHA256,
        "flash_predecessor_sha256": "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247",
        "cleanup_ok": False,
    }.items():
        if type(manifest.get(key)) is not type(expected) or manifest.get(key) != expected:
            raise ValueError(f"read source manifest field {key!r} is not exact")
    manifest_attestation = _fixed_attestation(
        manifest.get("current_boot_attestation"),
        READ_CANDIDATE_SHA256,
        "read source manifest",
        require_paths=False,
    )
    _validate_source_fixed_op(manifest.get("fixed_op"), "read source manifest", terminal=True)
    _validate_source_transition(manifest.get("panic_transition"), "read source manifest")
    source_id = manifest.get("experiment_id")
    private_record = manifest.get("private_record")
    if not isinstance(private_record, Mapping) or private_record.get("filename") != source_raw_name or private_record.get("journal_filename") != source_journal_name:
        raise ValueError("read source private filenames are not fixed")
    if manifest.get("raw_snapshot_sha256") != sha256(raw_bytes) or manifest.get("raw_snapshot_size") != len(raw_bytes) or manifest.get("journal_sha256") != sha256(journal_bytes) or manifest.get("journal_size") != len(journal_bytes):
        raise ValueError("read source public/private hash binding is not exact")
    if raw.get("schema") != "sdm855-a90-inline-remapper-mid-private-v1" or raw.get("experiment_id") != source_id or raw.get("mode") != "read":
        raise ValueError("read source raw schema/experiment is not exact")
    _validate_source_target(raw.get("target"), "read source raw")
    _validate_source_control_binding(raw.get("control_manifest"), "read source raw")
    _validate_source_flash(raw.get("flash_journal"), "read source raw")
    expected_flash_path = (
        root / "evidence" / "private" /
        "verification-024-remapper-boot-flash-read.journal.json"
    ).resolve()
    for owner, owner_label in (
        (raw.get("flash_journal"), "read source raw"),
        (journal.get("flash_journal"), "read source journal"),
    ):
        if not isinstance(owner, Mapping) or owner.get("path") != str(expected_flash_path):
            raise ValueError(f"{owner_label} flash journal path is not fixed")
    flash_owner = raw.get("flash_journal")
    if not isinstance(flash_owner, Mapping):
        raise ValueError("read source raw flash binding is missing")
    try:
        flash_source = verify_flash_journal(
            expected_flash_path,
            "read",
            root=root,
        )
    except BaseException as exc:
        raise ValueError("read source flash journal is not a complete fixed producer receipt") from exc
    if (
        flash_owner.get("sha256") != flash_source.get("sha256")
        or flash_owner.get("size") != flash_source.get("size")
        or flash_owner.get("profile") != "read"
        or flash_owner.get("image_sha256") != READ_CANDIDATE_SHA256
        or flash_owner.get("readback_sha256") != READ_CANDIDATE_SHA256
        or flash_owner.get("predecessor_sha256") != CONTROL_CANDIDATE_SHA256
    ):
        raise ValueError("read source flash binding does not match the fixed producer journal")
    if not isinstance(journal.get("flash_journal"), Mapping) or dict(journal["flash_journal"]) != dict(raw["flash_journal"]):
        raise ValueError("read source journal flash binding differs")
    for key, expected in {
        "candidate_sha256": READ_CANDIDATE_SHA256,
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
    }.items():
        if type(raw.get(key)) is not type(expected) or raw.get(key) != expected:
            raise ValueError(f"read source raw field {key!r} is not exact")
    raw_attestation = _fixed_attestation(
        raw.get("current_boot_attestation"), READ_CANDIDATE_SHA256, "read source raw"
    )
    if raw_attestation.get("captured_sha256") != manifest_attestation.get("captured_sha256"):
        raise ValueError("read source current boot attestation differs")
    _validate_source_transition(raw.get("panic_transition"), "read source raw")
    fixed = raw.get("fixed_op")
    if isinstance(fixed, Mapping):
        raise ValueError("read source raw fixed_op must not be forged")
    if "fixed_op_measurement" not in raw or raw.get("fixed_op_measurement") is not None:
        raise ValueError("read source no-value receipt contains a fixed measurement")
    error = raw.get("error")
    error_argv = error.get("argv") if isinstance(error, Mapping) else None
    if not isinstance(error, Mapping) or error.get("transport_no_value") is not True or error.get("bounded") is not True or error.get("evidence_id") != "fixed_op_4" or error_argv != list(_fixed_op_argv_full()) or error.get("a90r_present") is not False:
        raise ValueError("read source lacks actual bounded transport no-value evidence")
    if set(error) != set(TRANSPORT_NO_VALUE_EVIDENCE_KEYS):
        raise ValueError("read source transport evidence fields are not the exact producer set")
    error_type = error.get("exception_type")
    if error_type != "TransportFailure" or not isinstance(error.get("exception_text"), str) or not error.get("exception_text") or len(error["exception_text"]) > 512 or error.get("payload_bounded") is not True or error.get("transcript_bounded") is not True:
        raise ValueError("read source transport exception is not bounded")
    if error.get("partial_evidence_present") is not True:
        raise ValueError("read source typed transport lacks retained partial evidence")
    if error.get("transcript_base64") is None:
        raise ValueError("read source typed transport retained no transcript")
    if error.get("end") is not None or error.get("partial_end") is not None:
        raise ValueError("read source transport contains a complete END frame")
    decoded_payload: bytes | None = None
    decoded_transcript: bytes | None = None
    for prefix in ("payload", "transcript"):
        if any(key not in error for key in (
            f"{prefix}_base64",
            f"{prefix}_sha256",
            f"{prefix}_size",
        )):
            raise ValueError("read source partial transport absence binding is missing")
        encoded = error.get(f"{prefix}_base64")
        digest = error.get(f"{prefix}_sha256")
        size = error.get(f"{prefix}_size")
        if encoded is None:
            if digest is not None or size is not None:
                raise ValueError("read source partial transport absence binding is malformed")
            continue
        if (
            not isinstance(encoded, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(size) is not int
            or size < 0
            or size > MAX_SOURCE_RECEIPT_BYTES
        ):
            raise ValueError("read source partial transport is not bounded")
        try:
            decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("read source partial transport is malformed") from exc
        if len(decoded) != size or sha256(decoded) != digest or b"A90R" in decoded or b"A90P1 END" in decoded:
            raise ValueError("read source partial transport is not a no-value frame")
        if prefix == "transcript":
            decoded_transcript = decoded
        else:
            decoded_payload = decoded
    _validate_source_partial_begin_binding(
        error, decoded_transcript, list(_fixed_op_argv_full()), "read source transport"
    )
    _validate_source_partial_payload_relation(
        decoded_payload, decoded_transcript, "read source transport"
    )
    if not _inline_is_transport_no_value_payload(decoded_payload):
        raise ValueError(
            "read source transport post-BEGIN bytes are not an exact run dispatch prefix"
        )
    _validate_source_frame_list(raw.get("frames"), "read source raw")
    _validate_source_frame_list(journal.get("frames"), "read source journal")
    _require_source_panic_frames_equal(
        raw.get("frames"), journal.get("frames"), "read source"
    )
    if journal.get("schema") != "sdm855-a90-inline-remapper-mid-journal-v1" or journal.get("experiment_id") != source_id or journal.get("mode") != "read" or journal.get("status") != "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED":
        raise ValueError("read source journal is not the fixed ambiguous terminal")
    if journal.get("error") != error:
        raise ValueError("read source raw/journal transport errors differ")
    _validate_source_fixed_op(journal.get("fixed_op"), "read source journal")
    if "fixed_op_measurement" not in journal or journal.get("fixed_op_measurement") is not None:
        raise ValueError("read source journal contains a fixed measurement")
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
    }.items():
        if type(journal.get(key)) is not type(expected) or journal.get(key) != expected:
            raise ValueError(f"read source journal field {key!r} is not exact")
    journal_attestation = _fixed_attestation(
        journal.get("current_boot_attestation"), READ_CANDIDATE_SHA256, "read source journal"
    )
    if journal_attestation.get("captured_sha256") != raw_attestation.get("captured_sha256"):
        raise ValueError("read source journal current boot attestation differs")
    _validate_source_transition(journal.get("panic_transition"), "read source journal")
    _validate_source_control_binding(journal.get("control_manifest"), "read source journal")
    if not isinstance(journal.get("control_manifest"), Mapping) or dict(journal["control_manifest"]) != dict(raw["control_manifest"]):
        raise ValueError("read source journal control binding differs")
    _validate_source_panic_frames(journal.get("frames"), "read source journal")
    raw_boot_id = raw.get("boot_id_before_read")
    if not isinstance(raw_boot_id, str) or BOOT_ID_RE.fullmatch(raw_boot_id) is None:
        raise ValueError("read source private pre-read boot_id is malformed")
    boot_hash = sha256(raw_boot_id.encode("ascii"))
    for owner in (manifest, raw, journal):
        if owner.get("boot_id_before_read_sha256") != boot_hash:
            raise ValueError("read source pre-read boot_id hash binding differs")
    if journal.get("boot_id_before_read") != raw_boot_id:
        raise ValueError("read source journal pre-read boot_id differs")
    raw_target = raw.get("target")
    journal_target = journal.get("target")
    if not isinstance(raw_target, Mapping) or not isinstance(journal_target, Mapping):
        raise ValueError("read source target facts are missing")
    if dict(raw_target) != dict(journal_target):
        raise ValueError("read source raw/journal target facts differ")
    _validate_source_frame_payload_semantics(
        raw.get("frames"),
        target=raw_target,
        attestation=raw_attestation,
        candidate_sha256=READ_CANDIDATE_SHA256,
        candidate_size=BOOT_PREFIX_SIZE,
        boot_id_before_read=raw_boot_id,
        label="read source raw",
    )
    _validate_source_frame_payload_semantics(
        journal.get("frames"),
        target=journal_target,
        attestation=journal_attestation,
        candidate_sha256=READ_CANDIDATE_SHA256,
        candidate_size=BOOT_PREFIX_SIZE,
        boot_id_before_read=raw_boot_id,
        label="read source journal",
    )
    _validate_source_semantic_claim(
        root,
        manifest,
        raw,
        journal,
        mode="read",
        candidate_sha256=READ_CANDIDATE_SHA256,
        label="read source",
    )
    completed = manifest.get("completed_utc")
    if not isinstance(completed, str) or raw.get("completed_utc") != completed or journal.get("completed_utc") != completed:
        raise ValueError("read source completion times are not exact")
    return {
        "experiment_id": source_experiment_id,
        "manifest_sha256": sha256(manifest_bytes),
        "manifest_size": len(manifest_bytes),
        "raw_sha256": sha256(raw_bytes),
        "raw_size": len(raw_bytes),
        "journal_sha256": sha256(journal_bytes),
        "journal_size": len(journal_bytes),
        "completed_utc": completed,
        "source_pre_read_boot_id": raw_boot_id,
        "source_pre_read_boot_id_sha256": boot_hash,
    }


_SOURCE_FRAME_KEYS = frozenset(
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
_SOURCE_FRAME_BEGIN_KEYS = frozenset({"cmd", "seq", "argc", "flags"})
_SOURCE_FRAME_END_KEYS = frozenset(
    {"cmd", "seq", "rc", "errno", "duration_ms", "flags", "status"}
)
_CANONICAL_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_CANONICAL_SIGNED_DECIMAL_RE = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")


def _source_payload_line_variants(expected: bytes) -> frozenset[bytes]:
    if not expected:
        return frozenset({b""})
    if expected.endswith(b"\n"):
        stem = expected[:-1]
        return frozenset({stem + b"\n", stem + b"\r\n"})
    return frozenset({expected, expected + b"\n", expected + b"\r\n"})


def _validate_source_protocol_tail(
    transcript: bytes, end_match: re.Match[bytes], label: str
) -> None:
    tail = transcript[end_match.end() :]
    if tail not in {
        b"",
        b"a90:/# ",
        b"a90:/# \n",
        b"a90:/# \r\n",
    }:
        raise ValueError(f"{label} transcript has an unexpected suffix")
_SOURCE_FRAME_ARGV: dict[str, tuple[str, ...]] = {
    "version_before": ("version",),
    "cmdline_before": ("cat", "/proc/cmdline"),
    "soc_id_before": ("cat", "/sys/devices/soc0/soc_id"),
    "selftest_before": ("selftest", "status"),
    "panic_before": ("cat", "/proc/sys/kernel/panic_on_oops"),
    "boot_id_before_read": ("cat", BOOT_ID_PATH),
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
        "run", "/bin/toybox", "mkdir", "-p", "/tmp/a90-native"
    ),
    "boot_attest_stat_node": (
        "stat", "/tmp/a90-native/verification-024-sda24"
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
for _source_id, _source_path in (
    ("boot_attest_remove_node", BOOT_ATTEST_NODE),
    ("boot_attest_remove_file", BOOT_ATTEST_FILE),
    ("boot_attest_node_absent", BOOT_ATTEST_NODE),
    ("boot_attest_file_absent", BOOT_ATTEST_FILE),
    ("boot_attest_pre_node_absent", BOOT_ATTEST_NODE),
    ("boot_attest_pre_file_absent", BOOT_ATTEST_FILE),
):
    if "remove_" in _source_id:
        _SOURCE_FRAME_ARGV[_source_id] = (
            "run", "/bin/toybox", "rm", "-f", _source_path
        )
    else:
        _SOURCE_FRAME_ARGV[_source_id] = (
            "run", "/bin/toybox", "test", "!", "-e", _source_path
        )
        _SOURCE_FRAME_ARGV[_source_id + "_not_symlink"] = (
            "run", "/bin/toybox", "test", "!", "-L", _source_path
        )


def _source_frame_argv(
    evidence_id: object,
    *,
    uevent: Mapping[str, object] | None = None,
) -> tuple[str, ...] | None:
    if not isinstance(evidence_id, str):
        return None
    if re.fullmatch(r"stophud_[1-3]", evidence_id):
        return ("stophud",)
    if evidence_id == "fixed_op_4":
        return tuple(_fixed_op_argv_full())
    if evidence_id == "boot_attest_mknod":
        if uevent is None:
            return None
        validated = _validate_source_uevent_mapping(uevent, "source frame")
        return (
            "mknodb",
            BOOT_ATTEST_NODE,
            validated["MAJOR"],
            validated["MINOR"],
        )
    return _SOURCE_FRAME_ARGV.get(evidence_id)


def _source_expected_full_frame_ids(stop_count: int) -> list[str]:
    if type(stop_count) is not int or not 1 <= stop_count <= STOPHUD_MAX_ATTEMPTS:
        raise ValueError(f"inline stophud frame count is outside the fixed 1..3 bound")
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
    return ids


def _source_decode_frame_bytes(
    encoded: object, size: object, digest: object, label: str
) -> bytes:
    if not isinstance(encoded, str) or len(encoded) > MAX_SOURCE_RECEIPT_BYTES * 2:
        raise ValueError(f"{label} base64 is missing or oversized")
    if type(size) is not int or size < 0 or size > MAX_SOURCE_RECEIPT_BYTES:
        raise ValueError(f"{label} size is not bounded")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError(f"{label} hash is malformed")
    try:
        decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} base64 is malformed") from exc
    if len(decoded) != size or sha256(decoded) != digest:
        raise ValueError(f"{label} hash/size does not match bytes")
    return decoded


def _validate_source_protocol_frame(
    frame: object,
    evidence_id: str,
    argv: tuple[str, ...],
    label: str,
    *,
    expected_payload: bytes | None = None,
    expected_rc: str = "0",
    expected_status: str = "ok",
) -> None:
    if not isinstance(frame, Mapping) or set(frame) != _SOURCE_FRAME_KEYS:
        raise ValueError(f"{label} fields are not the exact producer frame schema")
    if frame.get("evidence_id") != evidence_id or frame.get("argv") != list(argv):
        raise ValueError(f"{label} evidence ID/argv is not exact")
    begin = frame.get("begin")
    end = frame.get("end")
    if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
        raise ValueError(f"{label} begin/end is missing")
    if set(begin) != _SOURCE_FRAME_BEGIN_KEYS or set(end) != _SOURCE_FRAME_END_KEYS:
        raise ValueError(f"{label} begin/end fields are not exact")
    seq = begin.get("seq")
    if (
        begin.get("cmd") != argv[0]
        or end.get("cmd") != argv[0]
        or not isinstance(seq, str)
        or _CANONICAL_DECIMAL_RE.fullmatch(seq) is None
        or end.get("seq") != seq
        or begin.get("argc") != str(len(argv))
        or begin.get("flags") != _protocol_flags_for_argv(argv)
        or end.get("rc") != expected_rc
        or not isinstance(end.get("errno"), str)
        or _CANONICAL_DECIMAL_RE.fullmatch(end.get("errno", "")) is None
        or end.get("errno") != _protocol_expected_errno(expected_rc)
        or not isinstance(end.get("duration_ms"), str)
        or _CANONICAL_DECIMAL_RE.fullmatch(end.get("duration_ms", "")) is None
        or end.get("flags") != _protocol_flags_for_argv(argv)
        or end.get("status") != expected_status
    ):
        raise ValueError(f"{label} begin/end sequence or terminal is not exact")
    payload = _source_decode_frame_bytes(
        frame.get("payload_base64"),
        frame.get("payload_size"),
        frame.get("payload_sha256"),
        f"{label} payload",
    )
    transcript = _source_decode_frame_bytes(
        frame.get("transcript_base64"),
        frame.get("transcript_size"),
        frame.get("transcript_sha256"),
        f"{label} transcript",
    )
    if argv == STOPHUD_ARGV:
        try:
            validate_stophud_evidence_sizes(payload, transcript)
        except BaseException as exc:
            raise ValueError(f"{label} stophud evidence size is not bounded") from exc
    if expected_payload is not None and payload not in _source_payload_line_variants(expected_payload):
        raise ValueError(f"{label} payload is not exact")
    begins = list(BEGIN_RE.finditer(transcript))
    ends = list(END_RE.finditer(transcript))
    if (
        transcript.count(b"A90P1 BEGIN") != len(begins)
        or transcript.count(b"A90P1 END") != len(ends)
        or len(begins) != 1
        or len(ends) != 1
    ):
        raise ValueError(f"{label} transcript framing is not singular")
    try:
        parsed = parse_last_frame(transcript, argv[0])
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError(f"{label} transcript is not complete") from exc
    if parsed.begin != dict(begin) or parsed.end != dict(end) or parsed.payload != payload:
        raise ValueError(f"{label} transcript does not bind begin/end/payload")
    body = transcript[begins[0].end() : ends[0].start()]
    _validate_source_protocol_tail(transcript, ends[0], label)
    if not _inline_protocol_terminal_and_tail_valid(
        transcript, begins[0], ends[0], argv, end
    ):
        raise ValueError(f"{label} terminal/tail is not exact")
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
        raise ValueError(f"{label} transcript terminal marker is not bound")
    if evidence_id != "fixed_op_4" and (b"A90R" in payload or b"A90R" in transcript):
        raise ValueError(f"{label} contains a hidden fixed-op result")


def _validate_source_frame_list(frames: object, label: str) -> None:
    if not isinstance(frames, list) or not frames:
        raise ValueError(f"{label} frames are missing")
    if any(
        isinstance(item, Mapping)
        and item.get("evidence_id") in {"panic_set_1", "panic_restore_verify"}
        for item in frames
    ):
        raise ValueError(f"{label} no-value frames contain a restore exchange")
    stop_ids = [
        item.get("evidence_id")
        for item in frames
        if isinstance(item, Mapping)
        and isinstance(item.get("evidence_id"), str)
        and re.fullmatch(r"stophud_[1-3]", item["evidence_id"])
    ]
    if stop_ids != [f"stophud_{index}" for index in range(1, len(stop_ids) + 1)]:
        raise ValueError(f"{label} stophud frame IDs are not contiguous")
    if not 1 <= len(stop_ids) <= STOPHUD_MAX_ATTEMPTS:
        raise ValueError(f"{label} requires one to three stophud frames")
    counts: dict[str, int] = {}
    duplicate_ids = {
        "boot_attest_remove_node",
        "boot_attest_remove_file",
        "boot_attest_node_absent",
        "boot_attest_node_absent_not_symlink",
        "boot_attest_file_absent",
        "boot_attest_file_absent_not_symlink",
    }
    frame_ids = [
        item.get("evidence_id") if isinstance(item, Mapping) else None
        for item in frames
    ]
    stop_count = len(stop_ids)
    expected_ids = _source_expected_full_frame_ids(stop_count)
    actual_ids = [item for item in frame_ids if isinstance(item, str)]
    if actual_ids != expected_ids:
        raise ValueError(f"{label} frame sequence contains extra or missing records")
    for index, frame in enumerate(frames):
        if not isinstance(frame, Mapping):
            raise ValueError(f"{label}[{index}] frame is not an object")
        evidence_id = frame.get("evidence_id")
        if evidence_id == "boot_attest_mknod":
            argv = _validate_source_mknod_argv(
                frame.get("argv"), f"{label}[{index}]"
            )
        else:
            argv = _source_frame_argv(evidence_id)
        if not isinstance(evidence_id, str) or argv is None:
            raise ValueError(f"{label}[{index}] frame ID is not allowlisted")
        if evidence_id == "fixed_op_4":
            raise ValueError(f"{label} no-value frames contain fixed_op_4")
        counts[evidence_id] = counts.get(evidence_id, 0) + 1
        if counts[evidence_id] > (2 if evidence_id in duplicate_ids else 1):
            raise ValueError(f"{label} frame ID {evidence_id!r} is duplicated")
        expected_rc = "0"
        expected_status = "ok"
        if evidence_id.startswith("stophud_"):
            attempt = int(evidence_id.rsplit("_", 1)[1])
            expected_rc = "-16" if attempt < len(stop_ids) else "0"
            expected_status = "busy" if attempt < len(stop_ids) else "ok"
        _validate_source_protocol_frame(
            frame,
            evidence_id,
            argv,
            f"{label}[{index}]",
            expected_rc=expected_rc,
            expected_status=expected_status,
        )
        if evidence_id.startswith("stophud_"):
            stop_payload = _source_decode_frame_bytes(
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
                raise ValueError(
                    f"{label}[{index}] stophud payload is not canonical"
                ) from exc
    _validate_source_panic_frames(frames, label)


def _source_semantic_single_line(payload: bytes, label: str) -> str:
    if b"\r" in payload.replace(b"\r\n", b""):
        raise ValueError(f"{label} contains a bare CR")
    if payload.endswith(b"\r\n"):
        body = payload[:-2]
    elif payload.endswith(b"\n"):
        body = payload[:-1]
    else:
        body = payload
    if not body or b"\n" in body or b"\r" in body or body[:1] in b" \t" or body[-1:] in b" \t":
        raise ValueError(f"{label} is not one exact line")
    try:
        return body.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not ASCII") from exc


def _source_semantic_lines(payload: bytes, label: str) -> list[str]:
    """Decode an optional-single-terminated native line payload.

    A90P1 frame parsing leaves the command payload's final line ending
    intact when it was present, but a command is also allowed to return the
    final line without LF/CRLF.  Accept only those two forms and reject bare
    CR, NUL, empty internal lines, and double terminal newlines.
    """

    if b"\r" in payload.replace(b"\r\n", b""):
        raise ValueError(f"{label} contains a bare CR")
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized.endswith(b"\n"):
        body = normalized[:-1]
    else:
        body = normalized
    if not body or body.endswith(b"\n") or b"\x00" in body:
        raise ValueError(f"{label} has empty or duplicate lines")
    try:
        lines = body.decode("ascii", errors="strict").split("\n")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not ASCII") from exc
    if any(not line for line in lines):
        raise ValueError(f"{label} has empty internal lines")
    return lines


_SOURCE_SEMANTIC_DUPLICATE_FRAME_IDS = frozenset(
    {
        "boot_attest_remove_node",
        "boot_attest_remove_file",
        "boot_attest_node_absent",
        "boot_attest_node_absent_not_symlink",
        "boot_attest_file_absent",
        "boot_attest_file_absent_not_symlink",
    }
)


def _source_semantic_payloads(frames: object, label: str) -> list[tuple[str, bytes]]:
    """Decode source payloads in order without collapsing repeated cleanup IDs."""

    if not isinstance(frames, list):
        raise ValueError(f"{label} frames are missing")
    result: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for index, frame in enumerate(frames):
        if not isinstance(frame, Mapping) or not isinstance(frame.get("evidence_id"), str):
            raise ValueError(f"{label}[{index}] frame identity is malformed")
        evidence_id = frame["evidence_id"]
        payload = _source_decode_frame_bytes(
            frame.get("payload_base64"),
            frame.get("payload_size"),
            frame.get("payload_sha256"),
            f"{label} {evidence_id} payload",
        )
        if evidence_id in seen and evidence_id not in _SOURCE_SEMANTIC_DUPLICATE_FRAME_IDS:
            raise ValueError(f"{label} duplicate {evidence_id!r} payloads differ")
        seen.add(evidence_id)
        result.append((evidence_id, payload))
    return result


def _source_semantic_selftest(payload: bytes, label: str) -> Mapping[str, int]:
    lines = _source_semantic_lines(payload, label)
    if len(lines) != 1 or re.fullmatch(
        r"selftest: pass=[0-9]+ warn=[0-9]+ fail=[0-9]+ duration=[0-9]+ms entries=[0-9]+",
        lines[0],
    ) is None:
        raise ValueError(f"{label} selftest framing is not exact")
    try:
        parsed = _inline_parse_selftest(payload, label)
    except BaseException as exc:
        raise ValueError(f"{label} selftest values are not exact") from exc
    return parsed


_V024_DISPLAY_RE = re.compile(
    r"display: [0-9]+x[0-9]+"
    r"(?: connector=[0-9]+)?(?: crtc=[0-9]+)?(?: fb=[0-9]+)?\Z"
)


def _parse_v024_version_payload(payload: bytes, label: str) -> dict[str, str]:
    """Parse exact V2321 identity plus the permitted owner/display metadata."""

    if b"\r" in payload.replace(b"\r\n", b""):
        raise ValueError(f"{label} version payload contains a bare CR")
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized.endswith(b"\n"):
        normalized = normalized[:-1]
    if not normalized or b"\n\n" in normalized or b"\x00" in normalized:
        raise ValueError(f"{label} version payload has empty framing")
    try:
        lines = normalized.decode("ascii", errors="strict").split("\n")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} version payload is not ASCII") from exc
    if any(not line for line in lines):
        raise ValueError(f"{label} version payload has an empty line")
    expected = [
        f"{EXPECTED_VERSION} ({EXPECTED_RUNTIME_BUILD})",
        f"version: {EXPECTED_RUNTIME} {EXPECTED_BUILD}",
        f"kernel: {EXPECTED_KERNEL}",
    ]
    identity = [
        line
        for line in lines
        if line.startswith(("A90 Linux init ", "version: ", "kernel: "))
    ]
    if identity != expected:
        raise ValueError(f"{label} version identity lines are missing, conflicting, or reordered")
    if sum(line == "made by device owner" for line in lines) > 1:
        raise ValueError(f"{label} version owner metadata is duplicated")
    display_lines = [line for line in lines if line.startswith("display: ")]
    if len(display_lines) > 1:
        raise ValueError(f"{label} version display metadata is duplicated")
    for line in lines:
        if line in expected or line == "made by device owner":
            continue
        if _V024_DISPLAY_RE.fullmatch(line) is None:
            raise ValueError(f"{label} version metadata line is not exact")
    return {
        "runtime_version": EXPECTED_RUNTIME,
        "runtime_build": EXPECTED_RUNTIME_BUILD,
        "kernel": EXPECTED_KERNEL,
    }


def _source_semantic_toybox_body(payload: bytes, label: str) -> bytes:
    try:
        return _inline_parse_toybox_payload(payload, label)
    except BaseException as exc:
        raise ValueError(f"{label} toybox wrapper is not one run/exit-0 record") from exc


def _validate_source_frame_payload_semantics(
    frames: object,
    *,
    target: Mapping[str, object],
    attestation: Mapping[str, object],
    candidate_sha256: str,
    candidate_size: int,
    boot_id_before_read: str,
    label: str,
) -> None:
    """Bind every source frame payload to the fixed read receipt facts."""

    ordered_payloads = _source_semantic_payloads(frames, label)
    payloads: dict[str, bytes] = {}
    stop_ids = [
        evidence_id
        for evidence_id, _payload in ordered_payloads
        if evidence_id.startswith("stophud_")
    ]
    for evidence_id, payload in ordered_payloads:
        payloads.setdefault(evidence_id, payload)
        if evidence_id.startswith("stophud_"):
            attempt = int(evidence_id.rsplit("_", 1)[1])
            expected_rc = -16 if attempt < len(stop_ids) else 0
            expected_status = "busy" if attempt < len(stop_ids) else "ok"
            try:
                validate_stophud_payload(payload, expected_rc, expected_status)
            except BaseException as exc:
                raise ValueError(
                    f"{label} {evidence_id} stophud payload is not canonical"
                ) from exc
    version_identity = _parse_v024_version_payload(
        payloads["version_before"], f"{label} version_before"
    )
    for key in ("runtime_version", "runtime_build", "kernel"):
        if target.get(key) != version_identity.get(key):
            raise ValueError(f"{label} version {key} differs from target")
    try:
        cmdline = _inline_parse_cmdline(payloads["cmdline_before"])
    except BaseException as exc:
        raise ValueError(f"{label} cmdline payload is malformed") from exc
    for key, expected in {
        "androidboot.em.model": EXPECTED_MODEL,
        "androidboot.bootloader": EXPECTED_BOOTLOADER,
        "androidboot.debug_level": "0x494d",
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
    }.items():
        if cmdline.get(key) != expected:
            raise ValueError(f"{label} cmdline {key} is not exact")
    if target.get("model") != cmdline.get("androidboot.em.model") or target.get("bootloader") != cmdline.get("androidboot.bootloader") or target.get("debug_level") != cmdline.get("androidboot.debug_level"):
        raise ValueError(f"{label} cmdline identity differs from target")
    if target.get("force_upload") not in {"0", cmdline.get("androidboot.force_upload")} or target.get("dump_sink") not in {"0", cmdline.get("sec_debug.dump_sink")}:
        raise ValueError(f"{label} cmdline zero pins differ from target")
    if _source_semantic_single_line(payloads["soc_id_before"], f"{label} soc_id_before") != "339":
        raise ValueError(f"{label} soc_id_before is not 339")
    if _source_semantic_single_line(payloads["boot_id_before_read"], f"{label} boot_id_before_read") != boot_id_before_read:
        raise ValueError(f"{label} boot_id_before_read differs from bound boot")
    selftest = _source_semantic_selftest(payloads["selftest_before"], f"{label} selftest_before")
    if not isinstance(target.get("selftest_before"), Mapping) or dict(selftest) != dict(target["selftest_before"]):
        raise ValueError(f"{label} selftest_before differs from target summary")
    uevent = _parse_source_uevent_payload(
        payloads["boot_sysfs_uevent"], f"{label} uevent"
    )
    if attestation.get("sysfs_uevent") != uevent:
        raise ValueError(f"{label} boot sysfs uevent differs from attestation")
    if _source_semantic_single_line(payloads["boot_sysfs_size"], f"{label} boot size") != "131072" or attestation.get("sectors") != 131072:
        raise ValueError(f"{label} boot sysfs size differs from attestation")
    if _source_semantic_single_line(payloads["boot_sysfs_ro"], f"{label} boot ro") != "0" or attestation.get("ro") != 0:
        raise ValueError(f"{label} boot sysfs ro differs from attestation")
    mknod_frames = [
        frame
        for frame in frames
        if isinstance(frame, Mapping)
        and frame.get("evidence_id") == "boot_attest_mknod"
    ]
    if len(mknod_frames) != 1:
        raise ValueError(f"{label} boot_attest_mknod frame count is not exact")
    mknod_argv = _validate_source_mknod_argv(
        mknod_frames[0].get("argv"), f"{label} boot_attest_mknod"
    )
    if mknod_argv[2:] != (uevent["MAJOR"], uevent["MINOR"]):
        raise ValueError(f"{label} mknod dev_t differs from boot uevent")
    try:
        stat_value = _inline_parse_stat_identity(
            payloads["boot_attest_stat_node"],
            uevent["MAJOR"],
            uevent["MINOR"],
        )
    except BaseException as exc:
        raise ValueError(f"{label} stat payload is malformed") from exc
    if stat_value != _source_expected_stat(uevent) or attestation.get("stat") != stat_value:
        raise ValueError(f"{label} stat differs from attestation")
    for evidence_id, payload in ordered_payloads:
        if evidence_id in _SOURCE_SEMANTIC_DUPLICATE_FRAME_IDS:
            try:
                body = _source_semantic_toybox_body(payload, f"{label} {evidence_id}")
            except BaseException as exc:
                raise ValueError(f"{label} {evidence_id} wrapper is malformed") from exc
            if body != b"":
                raise ValueError(f"{label} {evidence_id} has an unexpected body")
    for evidence_id in ("boot_attest_mkdir", "boot_attest_capture"):
        try:
            body = _source_semantic_toybox_body(payloads[evidence_id], f"{label} {evidence_id}")
        except BaseException as exc:
            raise ValueError(f"{label} {evidence_id} wrapper is malformed") from exc
        if body != b"":
            raise ValueError(f"{label} {evidence_id} has an unexpected body")
    if payloads["boot_attest_mknod"] != b"":
        raise ValueError(f"{label} boot_attest_mknod must have an empty payload")
    try:
        hash_body = _source_semantic_toybox_body(payloads["boot_attest_hash"], f"{label} hash")
        size_body = _source_semantic_toybox_body(payloads["boot_attest_size"], f"{label} size")
    except BaseException as exc:
        raise ValueError(f"{label} hash/size wrapper is malformed") from exc
    if hash_body != f"{candidate_sha256}  {BOOT_ATTEST_FILE}".encode("ascii") or size_body != f"{candidate_size} {BOOT_ATTEST_FILE}".encode("ascii"):
        raise ValueError(f"{label} captured hash/size differs from candidate")
    if attestation.get("expected_sha256") != candidate_sha256 or attestation.get("captured_sha256") != candidate_sha256 or attestation.get("expected_size") != candidate_size or attestation.get("captured_size") != candidate_size:
        raise ValueError(f"{label} attestation hash/size differs from candidate")


def _validate_source_panic_frames(frames: object, label: str) -> None:
    if not isinstance(frames, list):
        raise ValueError(f"{label} panic frames are missing")
    expected = {
        "panic_before": (("cat", "/proc/sys/kernel/panic_on_oops"), b"1\n"),
        "panic_set_0": (("writefile", "/proc/sys/kernel/panic_on_oops", "0"), b""),
        "panic_zero_verify": (("cat", "/proc/sys/kernel/panic_on_oops"), b"0\n"),
    }
    expected_ids = list(expected)
    observed_ids = [
        item.get("evidence_id")
        for item in frames
        if isinstance(item, Mapping)
        and item.get("evidence_id") in expected
    ]
    if observed_ids != expected_ids:
        raise ValueError(f"{label} panic frame order/count is not exact")
    for evidence_id, (argv, expected_payload) in expected.items():
        matches = [item for item in frames if isinstance(item, Mapping) and item.get("evidence_id") == evidence_id]
        if len(matches) != 1:
            raise ValueError(f"{label} requires one {evidence_id} frame")
        item = matches[0]
        _validate_source_protocol_frame(
            item,
            evidence_id,
            argv,
            f"{label} {evidence_id}",
            expected_payload=expected_payload,
        )


def _reject_hidden_complete_fixed_op_frames(frames: object, label: str) -> None:
    """Compatibility wrapper for structural source-frame validation.

    ``A90P1 END`` is part of every complete retained exchange.  This helper
    therefore validates the closed record/list schema instead of rejecting a
    valid END marker by substring.
    """

    _validate_source_frame_list(frames, label)


def _require_source_panic_frames_equal(
    raw_frames: object, journal_frames: object, label: str
) -> None:
    if not isinstance(raw_frames, list) or not isinstance(journal_frames, list):
        raise ValueError(f"{label} panic frame receipts are missing")
    if raw_frames != journal_frames:
        raise ValueError(f"{label} raw/journal frames differ")


def _validate_exact_runtime(
    version_payload: bytes, cmdline_payload: bytes
) -> dict[str, str]:
    """Require exact V2321/SM-A908N identity before reading last_kmsg."""

    cmdline = parse_cmdline(cmdline_payload)
    try:
        cmdline_text = cmdline_payload.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("live cmdline is not ASCII") from exc
    # The shared legacy parser retains relevant key/value pairs; close its
    # historical permissiveness around unknown flag-only/malformed tokens.
    for token in cmdline_text.split():
        if "=" not in token and token not in {"skip_initramfs", "rootwait", "ro"}:
            raise ValueError(f"live cmdline has malformed token: {token!r}")
    # validate_runtime checks the exact build, kernel, model, and bootloader
    # pins shared by the other A90 native tools.
    validate_runtime(version_payload, cmdline)
    _parse_v024_version_payload(version_payload, "live A90 version")
    if cmdline.get("androidboot.em.model") != EXPECTED_MODEL:
        raise ValueError("live cmdline model is not SM-A908N")
    if cmdline.get("androidboot.bootloader") != EXPECTED_BOOTLOADER:
        raise ValueError("live cmdline bootloader is not exact")
    if cmdline.get("androidboot.debug_level") != "0x494d":
        raise ValueError("live cmdline is not the exact DMID runtime")
    if cmdline.get("androidboot.force_upload") not in {"0", "0x0"}:
        raise ValueError("live cmdline force_upload is not zero")
    if cmdline.get("sec_debug.dump_sink") not in {"0", "0x0"}:
        raise ValueError("live cmdline dump_sink is not zero")
    # EXPECTED_SOC is a fixed target pin carried into evidence.  The runtime
    # version/cmdline contract has no independent printable SoC field, so do
    # not pretend that this host-side constant is a new device measurement.
    return cmdline


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    if args.experiment_id != LAST_KMSG_EXPERIMENT_ID:
        raise ValueError("last-kmsg experiment ID is fixed to last-kmsg-final")
    if not getattr(args, "execute", False):
        raise ValueError("last-kmsg capture requires explicit --execute")
    if args.host != BRIDGE_HOST or args.port != BRIDGE_PORT:
        raise ValueError("collector only accepts the exact loopback A90 bridge")
    if (
        not isinstance(args.timeout, (int, float))
        or isinstance(args.timeout, bool)
        or not math.isfinite(float(args.timeout))
        or not 0 < float(args.timeout) <= MAX_TIMEOUT_SEC
    ):
        raise ValueError(
            f"timeout must be finite and within 0 < timeout <= {MAX_TIMEOUT_SEC:g}"
        )
    args.timeout = float(args.timeout)

    root = _fixed_output_root(args)
    private_root = root / "evidence" / "private"
    manifest_root = root / "evidence" / "manifests"
    # The log is meaningful only as the consequence of this experiment's
    # exact one-shot read.  Bind the fixed source receipt before touching the
    # bridge or creating a new output namespace.
    source_experiment_id = READ_SOURCE_EXPERIMENT_ID
    if hasattr(args, "read_source_experiment_id"):
        supplied_source_id = getattr(args, "read_source_experiment_id")
        if supplied_source_id != READ_SOURCE_EXPERIMENT_ID:
            raise ValueError("read source experiment ID is fixed to verification-024-read")
    if hasattr(args, "read_source_path"):
        supplied_source_path = getattr(args, "read_source_path")
        expected_source_path = root / "evidence" / "private" / READ_SOURCE_JOURNAL_NAME
        try:
            supplied_path = Path(supplied_source_path)
            if not supplied_path.is_absolute():
                supplied_path = root / supplied_path
            _reject_symlink_components(supplied_path, "read source path selector")
            if supplied_path.resolve(strict=False) != expected_source_path.resolve(strict=False):
                raise ValueError("read source path is fixed to verification-024-read journal")
        except (TypeError, ValueError, OSError) as exc:
            if isinstance(exc, ValueError) and str(exc).startswith("read source path"):
                raise
            raise ValueError("read source path is fixed to verification-024-read journal") from exc
    source_read = _validate_source_read(root, source_experiment_id)
    source_read_public = {
        key: value
        for key, value in source_read.items()
        if key != "source_pre_read_boot_id"
    }
    private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest_root.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(private_root, 0o700)
    os.chmod(manifest_root, 0o755)
    raw_path = private_root / f"{args.experiment_id}.last_kmsg.bin"
    captured_raw_path = private_root / f"{args.experiment_id}.last_kmsg.raw.bin"
    record_path = private_root / f"{args.experiment_id}.private.json"
    journal_path = private_root / f"{args.experiment_id}.journal.json"
    manifest_path = manifest_root / f"{args.experiment_id}.manifest.json"
    for path in (raw_path, captured_raw_path, record_path, journal_path, manifest_path):
        _reject_existing(path)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    records: list[dict[str, object]] = []
    stophud_frames: list[dict[str, object]] = []
    # ``run_stophud`` deliberately stores a compact attempt projection.  Keep
    # the corresponding full private frames here so the finalizer can bind
    # every retry's BEGIN/END transcript and terminal rc/status, including a
    # busy->ok sequence, without changing the shared arbiter.
    stophud_exchange_frames: list[Frame] = []
    journal: dict[str, object] = {
        "schema": "sdm855-a90-last-kmsg-capture-private-v2",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "status": "PREFLIGHT",
        "effect_dispatched": False,
        "effect_replayed": False,
        "expected_target": {
            "model": EXPECTED_MODEL,
            "soc": EXPECTED_SOC,
            "runtime": EXPECTED_RUNTIME,
            "bridge_host": BRIDGE_HOST,
            "bridge_port": BRIDGE_PORT,
            "serial_device": BRIDGE_SERIAL_DEVICE,
            "serial_identity": BRIDGE_SERIAL_ID,
            "bridge_process_script": BRIDGE_PROCESS_SCRIPT,
            "bridge_process_script_path": str(BRIDGE_PROCESS_SCRIPT_PATH),
            "bridge_serial_glob_token": BRIDGE_SERIAL_GLOB_TOKEN,
        },
        "target": None,
        "target_verified": False,
        "transport_module": LOCAL_TRANSPORT_MODULE,
        "transport_source": LOCAL_TRANSPORT_SOURCE,
        "stophud": None,
        "stophud_frames": stophud_frames,
        "records": records,
        "read_source": source_read,
        "source_pre_read_boot_id": source_read["source_pre_read_boot_id"],
    }
    _create_initial_journal(journal_path, journal)

    def persist_stophud(attempts: list[dict[str, object]]) -> None:
        journal["stophud_attempts"] = attempts
        journal["stophud_frames"] = stophud_frames
        _write_journal(journal_path, journal)

    public_expected_target = {
        "model": EXPECTED_MODEL,
        "soc": EXPECTED_SOC,
        "runtime": EXPECTED_RUNTIME,
        "bootloader": EXPECTED_BOOTLOADER,
        "version": EXPECTED_VERSION,
        "build": EXPECTED_RUNTIME_BUILD,
        "kernel": EXPECTED_KERNEL,
    }
    incident_published = False

    def publish_incident(error: object) -> None:
        nonlocal incident_published
        if incident_published or manifest_path.exists() or manifest_path.is_symlink():
            return
        private_record: dict[str, object] = {
            "journal_filename": journal_path.name,
        }
        if raw_path.exists() and not raw_path.is_symlink():
            data = raw_path.read_bytes()
            private_record.update(
                {
                    "filename": raw_path.name,
                    "size": len(data),
                    "sha256": sha256(data),
                }
            )
        if captured_raw_path.exists() and not captured_raw_path.is_symlink():
            data = captured_raw_path.read_bytes()
            private_record["captured_log"] = {
                "filename": captured_raw_path.name,
                "size": len(data),
                "sha256": sha256(data),
            }
        _publish_incident_manifest(
            manifest_path,
            experiment_id=args.experiment_id,
            started=started,
            status=str(journal.get("status", "INCIDENT")),
            error=error,
            journal_path=journal_path,
            expected_target=public_expected_target,
            target_verified=bool(journal.get("target_verified")),
            target=journal.get("target")
            if isinstance(journal.get("target"), Mapping)
            else None,
            effect_dispatched=bool(journal.get("effect_dispatched")),
            private_record=private_record,
        )
        incident_published = True

    def exchange_once(command: Command) -> Frame:
        try:
            frame = exchange(args.host, args.port, command, args.timeout)
        except BaseException as exc:
            incident = _partial_record(command, exc)
            records.append(incident)
            journal["records"] = records
            journal["status"] = "INCIDENT"
            journal["error"] = f"{type(exc).__name__}: {exc}"
            _write_journal(journal_path, journal)
            raise
        record = _frame_record(command, frame)
        records.append(record)
        journal["records"] = records
        _write_journal(journal_path, journal)
        begin = getattr(frame, "begin", {})
        end = getattr(frame, "end", {})
        if (
            not isinstance(begin, Mapping)
            or not isinstance(end, Mapping)
            or begin.get("cmd") != command.argv[0]
            or end.get("cmd") != command.argv[0]
            or begin.get("seq") != end.get("seq")
        ):
            raise ValueError(f"{command.evidence_id} frame command/sequence is not exact")
        try:
            rc = int(end.get("rc"), 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{command.evidence_id} frame rc is malformed") from exc
        if rc != 0 or end.get("status") != "ok":
            raise ValueError(f"{command.evidence_id} frame did not complete successfully")
        return frame

    try:
        # Local bridge/serial binding is host-side and precedes the first
        # device command.  stophud is the first substantive device command.
        bridge_binding = validate_bridge_binding()
        if not isinstance(bridge_binding, Mapping):
            raise ValueError("initial bridge binding is not an object")

        def guarded_stophud_exchange(
            exchange_host: str,
            exchange_port: int,
            command: Command,
            exchange_timeout: float,
            **kwargs: object,
        ) -> Frame:
            # ``run_stophud`` calls this immediately before each attempt,
            # including every busy retry.  Refuse the attempt itself if the
            # exact initial serial/process binding has drifted.
            current = revalidate_bridge_binding(bridge_binding)
            if not isinstance(current, Mapping) or not _bridge_bindings_match(
                bridge_binding, current
            ):
                raise ValueError("bridge binding drifted before stophud attempt")
            frame = exchange(
                exchange_host,
                exchange_port,
                command,
                exchange_timeout,
                **kwargs,
            )
            stophud_exchange_frames.append(frame)
            return frame

        def validate_stophud_frame(frame: object) -> object:
            return _inline_validate_complete_frame(
                frame,
                STOPHUD_ARGV,
                "stophud attempt",
                allow_stophud_busy=True,
            )

        stophud = run_stophud(
            args.host,
            args.port,
            args.timeout,
            guarded_stophud_exchange,
            frame_records=stophud_frames,
            persist=persist_stophud,
            validate_frame=validate_stophud_frame,
        )
        if (
            not isinstance(stophud, Mapping)
            or not isinstance(stophud.get("attempts"), list)
            or not 1 <= len(stophud.get("attempts", [])) <= STOPHUD_MAX_ATTEMPTS
            or len(stophud_exchange_frames) != len(stophud_frames)
            or len(stophud_frames) > STOPHUD_MAX_ATTEMPTS
        ):
            raise ValueError("stophud exchange/frame count is not exact")
        for record, frame in zip(stophud_frames, stophud_exchange_frames):
            transcript = getattr(frame, "transcript", None)
            if not isinstance(transcript, bytes):
                raise ValueError("stophud full transcript is missing")
            record["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
        journal["stophud"] = stophud
        journal["stophud_frames"] = stophud_frames
        post_stophud_binding = revalidate_bridge_binding(bridge_binding)
        if not isinstance(post_stophud_binding, Mapping) or not _bridge_bindings_match(
            bridge_binding, post_stophud_binding
        ):
            raise ValueError("bridge binding drifted after stophud")
        journal["bridge_binding"] = bridge_binding
        journal["post_stophud_bridge_binding"] = post_stophud_binding
        _write_journal(journal_path, journal)

        version_frame = exchange_once(Command("version_before", ("version",)))
        cmdline_frame = exchange_once(
            Command("cmdline_before", ("cat", "/proc/cmdline"))
        )
        cmdline = _validate_exact_runtime(version_frame.payload, cmdline_frame.payload)
        journal["target"] = {
            "model": EXPECTED_MODEL,
            "soc": EXPECTED_SOC,
            "runtime": EXPECTED_RUNTIME,
            "bootloader": EXPECTED_BOOTLOADER,
        }
        journal["target_verified"] = True
        _write_journal(journal_path, journal)
        # Rebind immediately before the one-shot log read.  The read is not
        # retried if this check or the read itself fails.
        live_binding = revalidate_bridge_binding(post_stophud_binding)
        if not isinstance(live_binding, Mapping) or not _bridge_bindings_match(
            post_stophud_binding, live_binding
        ):
            raise ValueError("bridge binding drifted before last_kmsg source read")
        journal["live_bridge_binding_before_last_kmsg"] = live_binding
        _write_journal(journal_path, journal)

        def guarded_read(command: Command) -> Frame:
            # The boot-id and last_kmsg reads are the causal join itself.  A
            # fresh exact revalidation belongs immediately before each read,
            # with no journal fsync or other device command between bind and
            # exchange.
            current = revalidate_bridge_binding(live_binding)
            if not isinstance(current, Mapping) or not _bridge_bindings_match(
                live_binding, current
            ):
                raise ValueError(f"bridge binding drifted before {command.evidence_id}")
            return exchange_once(command)

        current_boot_frame = guarded_read(
            Command("boot_id_after_source", ("cat", BOOT_ID_PATH))
        )
        current_boot_id = _parse_boot_id(
            current_boot_frame.payload, "current boot_id"
        )
        if current_boot_id == source_read["source_pre_read_boot_id"]:
            raise ValueError(
                "current boot_id did not change from the fixed read source boot"
            )
        journal.update(
            {
                "current_boot_id": current_boot_id,
                "current_boot_id_sha256": sha256(current_boot_id.encode("ascii")),
                "boot_id_changed": True,
            }
        )
        _write_journal(journal_path, journal)

        retained = guarded_read(Command("last_kmsg", ("cat", "/proc/last_kmsg")))
        journal["last_kmsg_read_once"] = True
        journal["records"] = records
        _write_journal(journal_path, journal)

        summary = marker_summary(retained.payload)
        if summary["exact_reset_signature"]["status"] != "EXACT_V024_MID_NONSECURE_WDT":
            # Preserve the one-shot binary read and stop here.  A malformed,
            # stale, reordered, duplicate, non-finite, or A90R-bearing log is
            # an incident/unknown observation; selftest is deliberately not a
            # follow-up that could obscure the evidence boundary.
            write_new(captured_raw_path, retained.payload, 0o600)
            signature_bytes = _signature_json_bytes(summary["exact_reset_signature"])
            write_new(raw_path, signature_bytes, 0o600)
            private_record = {
                "schema": "sdm855-a90-last-kmsg-capture-private-v2",
                "experiment_id": args.experiment_id,
                "started_utc": started,
                "completed_utc": dt.datetime.now(dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat(),
                "last_kmsg": {
                    "filename": raw_path.name,
                    "size": len(signature_bytes),
                    "sha256": sha256(signature_bytes),
                    "captured_log_filename": captured_raw_path.name,
                    "captured_log_size": len(retained.payload),
                    "captured_log_sha256": sha256(retained.payload),
                    "markers": summary,
                },
                "exact_reset_signature": summary["exact_reset_signature"],
                "journal_filename": journal_path.name,
            }
            write_new(record_path, json_bytes(private_record), 0o600)
            journal.update(
                {
                    "status": summary["exact_reset_signature"]["status"],
                    "retained_size": len(signature_bytes),
                    "retained_sha256": sha256(signature_bytes),
                    "captured_log_size": len(retained.payload),
                    "captured_log_sha256": sha256(retained.payload),
                    "private_record": record_path.name,
                    "raw_filename": raw_path.name,
                    "captured_log_filename": captured_raw_path.name,
                }
            )
            _write_journal(journal_path, journal)
            publish_incident(
                f"exact V024 reset signature status: {summary['exact_reset_signature']['status']}"
            )
            raise ValueError(
                f"last_kmsg exact reset signature was not accepted: "
                f"{summary['exact_reset_signature']['status']}"
            )

        # This is a separate read-only health observation.  It is never used
        # to replay last_kmsg and is only attempted after the exact signature
        # has been parsed successfully.
        # Persist the one-shot log and its derived signature before issuing
        # even this read-only follow-up.  A selftest transport failure must
        # leave independently hashable reconciliation evidence on disk.
        captured_raw_bytes = retained.payload
        write_new(captured_raw_path, captured_raw_bytes, 0o600)
        signature_bytes = _signature_json_bytes(summary["exact_reset_signature"])
        write_new(raw_path, signature_bytes, 0o600)
        journal.update(
            {
                "status": "SIGNATURE_VERIFIED_PENDING_SELFTEST",
                "retained_size": len(signature_bytes),
                "retained_sha256": sha256(signature_bytes),
                "captured_log_size": len(captured_raw_bytes),
                "captured_log_sha256": sha256(captured_raw_bytes),
                "raw_filename": raw_path.name,
                "captured_log_filename": captured_raw_path.name,
            }
        )
        _write_journal(journal_path, journal)
        after = exchange_once(Command("selftest_after", ("selftest", "status")))
        completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        private_record = {
            "schema": "sdm855-a90-last-kmsg-capture-private-v2",
            "experiment_id": args.experiment_id,
            "started_utc": started,
            "completed_utc": completed,
            "target": {
                "model": EXPECTED_MODEL,
                "soc": EXPECTED_SOC,
                "runtime": EXPECTED_RUNTIME,
                "cmdline": cmdline,
            },
            "transport_module": LOCAL_TRANSPORT_MODULE,
            "transport_source": LOCAL_TRANSPORT_SOURCE,
            "read_source": source_read,
            "source_pre_read_boot_id": source_read["source_pre_read_boot_id"],
            "current_boot_id": current_boot_id,
            "current_boot_id_sha256": sha256(current_boot_id.encode("ascii")),
            "boot_id_changed": True,
            "bridge_binding": bridge_binding,
            "post_stophud_bridge_binding": post_stophud_binding,
            "live_bridge_binding_before_last_kmsg": live_binding,
            "stophud": stophud,
            "stophud_frames": stophud_frames,
            "records": records,
            "last_kmsg": {
                "filename": raw_path.name,
                "size": len(signature_bytes),
                "sha256": sha256(signature_bytes),
                "markers": summary,
            },
            "captured_log": {
                "filename": captured_raw_path.name,
                "size": len(captured_raw_bytes),
                "sha256": sha256(captured_raw_bytes),
            },
            "selftest_status": after.end.get("status"),
            "exact_reset_signature": summary["exact_reset_signature"],
        }
        write_new(record_path, json_bytes(private_record), 0o600)
        journal.update(
            {
                "status": "COMPLETE",
                "completed_utc": completed,
                "private_record": record_path.name,
                "retained_size": len(signature_bytes),
                "retained_sha256": sha256(signature_bytes),
                "captured_log_size": len(captured_raw_bytes),
                "captured_log_sha256": sha256(captured_raw_bytes),
                "raw_filename": raw_path.name,
                "captured_log_filename": captured_raw_path.name,
                "records": records,
            }
        )
        _write_journal(journal_path, journal)
    except BaseException as exc:
        # ``exchange_once`` has already retained the command-level incident;
        # bridge/target failures before a command are also retained here.
        if journal.get("status") != "INCIDENT":
            journal["status"] = "PREFLIGHT_FAILED"
            journal["error"] = f"{type(exc).__name__}: {exc}"
            journal["records"] = records
            _write_journal(journal_path, journal)
        publish_incident(exc)
        raise

    version_record = next(
        item for item in records if item.get("evidence_id") == "version_before"
    )
    manifest = {
        "schema": "sdm855-a90-last-kmsg-capture-public-v2",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": journal["completed_utc"],
        "target_verified": True,
        "target_model": EXPECTED_MODEL,
        "soc": EXPECTED_SOC,
        "runtime": EXPECTED_RUNTIME,
        "transport_module": LOCAL_TRANSPORT_MODULE,
        "transport_source": LOCAL_TRANSPORT_SOURCE,
        "read_source": source_read_public,
        "source_pre_read_boot_id_sha256": source_read[
            "source_pre_read_boot_id_sha256"
        ],
        "current_boot_id_sha256": sha256(current_boot_id.encode("ascii")),
        "boot_id_changed": True,
        "reboot_dispatched": False,
        "commands": [
            "stophud",
            "version",
            "cat /proc/cmdline",
            "cat /proc/sys/kernel/random/boot_id",
            "cat /proc/last_kmsg",
            "selftest status",
        ],
        "stophud_accepted": bool(stophud.get("accepted")),
        "stophud_busy_retries": stophud.get("busy_retries", 0),
        "stophud_device_state_write": True,
        "other_device_writes": False,
        "last_kmsg_read_once": True,
        "version_status": version_record["end"]["status"],
        "selftest_status": after.end.get("status"),
        "exact_reset_signature": summary["exact_reset_signature"],
        "retained_size": len(signature_bytes),
        "retained_sha256": sha256(signature_bytes),
        "captured_log_size": len(captured_raw_bytes),
        "captured_log_sha256": sha256(captured_raw_bytes),
        "markers": summary,
        "private_record": {
            "filename": raw_path.name,
            "metadata_filename": record_path.name,
            "journal_filename": journal_path.name,
            "raw_filename": raw_path.name,
            "size": len(signature_bytes),
            "sha256": sha256(signature_bytes),
            "captured_log_filename": captured_raw_path.name,
            "captured_log_size": len(captured_raw_bytes),
            "captured_log_sha256": sha256(captured_raw_bytes),
            "git_ignored": True,
        },
        "bridge": {
            "host": BRIDGE_HOST,
            "port": BRIDGE_PORT,
            "binding_verified": True,
        },
        "limitations": [
            "The retained binary log is private; this manifest publishes only bounded hashes, sizes, and marker counts.",
            "last_kmsg is a one-shot read-only observation and is never retried after a transport ambiguity.",
        ],
    }
    # ``ordered_offsets`` is itself an ordered contract; json_bytes() sorts
    # object keys globally, so retain the signature's insertion order here.
    write_new(
        manifest_path,
        json.dumps(manifest, indent=2, ensure_ascii=True, sort_keys=False).encode()
        + b"\n",
        0o644,
    )
    return raw_path, manifest_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default=BRIDGE_HOST)
    parser.add_argument("--port", type=int, default=BRIDGE_PORT)
    parser.add_argument("--timeout", type=float, default=45.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    raw, manifest = collect(args)
    print(raw)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
