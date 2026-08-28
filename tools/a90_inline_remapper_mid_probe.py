#!/usr/bin/env python3
"""Run one fixed remapper operation on the exact A90 at ``DMID``.

Verification 024 has two already-built boot candidates.  ``control`` maps and
unmaps ``0x09248080`` without a bus load and must return ``0xc071``; ``read``
performs the one fixed 32-bit load from that mapping.  This host runner only
supplies op 4 with an empty argument tuple.  It cannot supply a physical
address, width, target, or value and it never retries an operation.

The runner binds the exact V2321/SM-A908N/SM8150 runtime and the exact
operator-owned A90 bridge before dispatch.  It uses the repository's local
partial-evidence-preserving A90P1 transport and a fixed ``ExtendedCommand``
buffer, attests the current boot prefix, durably arms the temporary
``panic_on_oops: 1 -> 0`` transition, restores and verifies ``1`` after a
returned operation, and never sends a command after a dispatch
timeout/disconnect.  A timeout, disconnect, or partial frame is retained as
``REFUSED_AT_MID_CANDIDATE`` (not a clean negative) and requires later
last-kmsg, rollback, and health evidence.
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
from typing import Any, Callable, Mapping, Sequence

try:
    from tools import a90_pa28_live as native_transport
    from tools.a90_acm_snapshot import (
        BEGIN_RE,
        END_RE,
        Command,
        json_bytes,
        parse_fields,
        parse_last_frame,
        write_new,
    )
    from tools.a90_autohud_arbitration import (
        STOPHUD_ARGV,
        STOPHUD_MAX_PAYLOAD_BYTES,
        STOPHUD_MAX_TRANSCRIPT_BYTES,
        STOPHUD_MAX_ATTEMPTS,
        STOPHUD_RETRY_DELAY_SEC,
        run_stophud,
        validate_stophud_evidence_sizes,
    )
    from tools.a90_twrp_remapper_boot_flash import (
        ALLOWED_PREDECESSORS,
        PASS_READBACK_AND_CLEANUP,
    )
    from tools.a90_twrp_system_boot import (
        TARGET_DEVICE as RECOVERY_TARGET_DEVICE,
        TARGET_MODEL as RECOVERY_TARGET_MODEL,
        TARGET_SERIAL_SHA256 as RECOVERY_TARGET_SERIAL_SHA256,
    )
    from tools.a90_pa28_live import (
        BRIDGE_HOST,
        BRIDGE_PORT,
        BRIDGE_PROCESS_SCRIPT,
        BRIDGE_PROCESS_SCRIPT_PATH,
        BRIDGE_SERIAL_DEVICE,
        BRIDGE_SERIAL_GLOB_TOKEN,
        BRIDGE_SERIAL_ID,
        EXPECTED_BUILD,
        EXPECTED_KERNEL,
        EXPECTED_MODEL,
        EXPECTED_RUNTIME,
        EXPECTED_RUNTIME_BUILD,
        EXPECTED_SOC,
        EXPECTED_VERSION,
        ExtendedCommand,
        exchange as native_exchange,
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    from tools import build_a90_inline_remapper_candidate as candidate
except ModuleNotFoundError:  # Direct execution from tools/.
    import a90_pa28_live as native_transport  # type: ignore
    from a90_acm_snapshot import (  # type: ignore
        BEGIN_RE,
        END_RE,
        Command,
        json_bytes,
        parse_fields,
        parse_last_frame,
        write_new,
    )
    from a90_autohud_arbitration import (  # type: ignore
        STOPHUD_ARGV,
        STOPHUD_MAX_PAYLOAD_BYTES,
        STOPHUD_MAX_TRANSCRIPT_BYTES,
        STOPHUD_MAX_ATTEMPTS,
        STOPHUD_RETRY_DELAY_SEC,
        run_stophud,
        validate_stophud_evidence_sizes,
    )
    from a90_twrp_remapper_boot_flash import (  # type: ignore
        ALLOWED_PREDECESSORS,
        PASS_READBACK_AND_CLEANUP,
    )
    from a90_twrp_system_boot import (  # type: ignore
        TARGET_DEVICE as RECOVERY_TARGET_DEVICE,
        TARGET_MODEL as RECOVERY_TARGET_MODEL,
        TARGET_SERIAL_SHA256 as RECOVERY_TARGET_SERIAL_SHA256,
    )
    from a90_pa28_live import (  # type: ignore
        BRIDGE_HOST,
        BRIDGE_PORT,
        BRIDGE_PROCESS_SCRIPT,
        BRIDGE_PROCESS_SCRIPT_PATH,
        BRIDGE_SERIAL_DEVICE,
        BRIDGE_SERIAL_GLOB_TOKEN,
        BRIDGE_SERIAL_ID,
        EXPECTED_BUILD,
        EXPECTED_KERNEL,
        EXPECTED_MODEL,
        EXPECTED_RUNTIME,
        EXPECTED_RUNTIME_BUILD,
        EXPECTED_SOC,
        EXPECTED_VERSION,
        ExtendedCommand,
        exchange as native_exchange,
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    import build_a90_inline_remapper_candidate as candidate  # type: ignore

try:
    from tools import a90_v024_control_retry as control_retry
except ModuleNotFoundError:  # Direct execution from tools/.
    import a90_v024_control_retry as control_retry  # type: ignore


# Use the repository's local, partial-evidence-preserving A90P1 transport.
# Tests replace this narrow name with a mock transport; production has no
# mutable external transport dependency.
exchange = native_exchange


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_EXPERIMENT_ID = "verification-024-control-r2"
CONTROL_PREDECESSOR_EXPERIMENT_ID = "verification-024-control"
READ_SOURCE_EXPERIMENT_ID = "verification-024-read"
FLASH_JOURNAL_PREFIX = "verification-024-remapper-boot-flash-"
MODE_CONTROL = candidate.MODE_CONTROL
MODE_READ = candidate.MODE_READ
MODES = (MODE_CONTROL, MODE_READ)
# ``MODES`` names the two inline operations.  Flash journals have one
# additional fixed profile consumed by the rollback finalizer.  Keep that
# profile in a separate allow-list so an operator cannot turn the inline
# operation selector into a caller-controlled flash namespace.
FLASH_MODES = (*MODES, "rollback")
OP_FIXED_READ = candidate.OP_FIXED_READ
CONTROL_SENTINEL = candidate.CONTROL_SENTINEL
MAP_FAILURE_RESULT = (1 << 64) - 1
BOOT_PREFIX_SIZE = 60_882_944
BOOT_BLOCK_NODE = "/dev/block/sda24"
BOOT_SYSFS_ROOT = "/sys/class/block/sda24"
BOOT_SYSFS_UEVENT = f"{BOOT_SYSFS_ROOT}/uevent"
BOOT_SYSFS_SIZE = f"{BOOT_SYSFS_ROOT}/size"
BOOT_SYSFS_RO = f"{BOOT_SYSFS_ROOT}/ro"
# These are experiment-owned, fixed paths.  No path supplied by a caller is
# ever interpolated into an A90 command.
BOOT_ATTEST_DIR = "/tmp/a90-native"
BOOT_ATTEST_NODE = f"{BOOT_ATTEST_DIR}/verification-024-sda24"
BOOT_ATTEST_FILE = f"{BOOT_ATTEST_DIR}/verification-024-boot-prefix.bin"
# Compatibility aliases for older callers.  Attestation never uses these
# values as an authority; the fixed sysfs uevent is parsed immediately before
# mknod/stat and supplies the exact strings for the current kernel dev_t.
BOOT_EXPECTED_MAJOR = "259"
BOOT_EXPECTED_MINOR = "8"
BOOT_MAJOR_MIN = 1
BOOT_MAJOR_MAX = 4095
BOOT_MINOR_MIN = 0
BOOT_MINOR_MAX = 1048575
BOOT_EXPECTED_PARTN = "24"
BOOT_EXPECTED_PARTNAME = "boot"
BOOT_EXPECTED_SECTORS = "131072"
FIXED_OP_MAGIC = 0xA90C0DE5DEADBEEF
FIXED_OP_BUFFER_SIZE = 0x58
FIXED_OP_NODE = "/sys/class/kgsl/kgsl-3d0/force_no_nap"
FIXED_OP_DMESG_TAIL = 16
# The device helper prints one canonical lowercase hexadecimal value.  Keep
# this line parser closed to that protocol spelling: no prefix/suffix,
# leading padding, second record, or uppercase alias can become a result.
FIXED_OP_A90R_LINE_RE = re.compile(rb"A90R(?P<value>[0-9a-f]{1,16})\Z")
# The native command table's ``flags`` field is serialized verbatim by
# cmdv1/cmdv1x.  Keep this one table shared by the producer's partial paths
# and every evidence consumer: CMD_NONE=0, CMD_BLOCKING=1<<1, and
# CMD_BACKGROUND=1<<3 in the pinned v319 source.
COMMAND_PROTOCOL_FLAGS: dict[str, str] = {
    "run": "0x2",
    "writefile": "0x0",
    "version": "0x0",
    "cat": "0x0",
    "selftest": "0x0",
    "mknodb": "0x0",
    "stat": "0x0",
    "stophud": "0x8",
}


def protocol_flags_for_argv(argv: Sequence[str]) -> str | None:
    """Return the exact native protocol flags for an allowlisted command."""

    if not argv or not isinstance(argv[0], str):
        return None
    return COMMAND_PROTOCOL_FLAGS.get(argv[0])


def protocol_expected_errno(rc: object) -> str | None:
    """Return the native ``a90_shell_result_errno`` value for one rc token."""

    if not isinstance(rc, str) or re.fullmatch(r"-?(?:0|[1-9][0-9]*)", rc) is None:
        return None
    if rc == "-0":
        return None
    value = int(rc, 10)
    return str(-value if value < 0 else 0)


TOYBOX_RUN_RE = re.compile(rb"run: pid=[1-9][0-9]*, q/Ctrl-C cancels")
TOYBOX_EXIT_RE = re.compile(rb"\[exit ([0-9]+)\]")
_PARTIAL_RUN_PREFIX = b"run: pid="
_PARTIAL_RUN_SUFFIX = b", q/Ctrl-C cancels"
_PROTOCOL_TERMINAL_RE = re.compile(
    rb"(?:^|\r?\n)\[(?P<kind>done|err|busy)\] "
    rb"(?P<text>[^\r\n]*)(?:\r\n|\n|\Z)"
)
_PROTOCOL_BUSY_TEXTS = frozenset(
    {
        b"power menu active; send hide/q before commands",
        b"auto menu active; hide/q before dangerous command",
        b"auto menu active; send hide/q before command",
    }
)
# ``a90_shell_print_result`` obtains negative-result text from the pinned
# native libc ``strerror(result_errno)`` call.  Do not accept an arbitrary
# parenthesized string in a retained transcript: only deterministic,
# source-exact spellings used by the supported errno surface are valid.
_PROTOCOL_ERRNO_MESSAGES: dict[int, bytes] = {
    1: b"Operation not permitted",
    2: b"No such file or directory",
    5: b"Input/output error",
    9: b"Bad file descriptor",
    11: b"Resource temporarily unavailable",
    12: b"Cannot allocate memory",
    13: b"Permission denied",
    16: b"Device or resource busy",
    17: b"File exists",
    19: b"No such device",
    20: b"Not a directory",
    22: b"Invalid argument",
    28: b"No space left on device",
    32: b"Broken pipe",
    35: b"Resource deadlock avoided",
    38: b"Function not implemented",
    39: b"Directory not empty",
    40: b"Too many levels of symbolic links",
    61: b"No data available",
    95: b"Operation not supported",
    110: b"Connection timed out",
    111: b"Connection refused",
    125: b"Operation canceled",
}
_PROTOCOL_ERR_WITH_ERRNO_RE = re.compile(
    rb"(?P<cmd>[^\s]+) rc=(?P<rc>-?(?:0|[1-9][0-9]*)) "
    rb"errno=(?P<errno>(?:0|[1-9][0-9]*)) "
    rb"\((?P<message>.+)\) \((?P<duration>(?:0|[1-9][0-9]*))ms\)\Z"
)
_PROTOCOL_ERR_NO_ERRNO_RE = re.compile(
    rb"(?P<cmd>[^\s]+) rc=(?P<rc>-?(?:0|[1-9][0-9]*)) "
    rb"\((?P<duration>(?:0|[1-9][0-9]*))ms\)\Z"
)


def protocol_terminal_and_tail_valid(
    transcript: bytes,
    begin_match: re.Match[bytes],
    end_match: re.Match[bytes],
    argv: Sequence[str],
    end: Mapping[str, object],
) -> bool:
    """Validate the native outer result marker and post-END prompt tail.

    The finalizer and last-kmsg source use this pure helper too, keeping a
    producer receipt from being accepted under a consumer-only interpretation
    of terminal framing.  Native ``a90_shell_print_result`` emits one
    command/duration-bound ``[done]`` or ``[err]`` line; controller-busy
    dispatch emits one of three exact ``[busy]`` lines.  Only the prompt tail
    emitted by the pinned shell is allowed after END.
    """

    if transcript[end_match.end() :] not in {
        b"",
        b"a90:/# ",
        b"a90:/# \n",
        b"a90:/# \r\n",
    }:
        return False
    body = transcript[begin_match.end() : end_match.start()]
    terminals = list(_PROTOCOL_TERMINAL_RE.finditer(body))
    if len(terminals) != 1 or terminals[0].end() != len(body):
        return False
    terminal = terminals[0]
    kind = terminal.group("kind")
    text = terminal.group("text")
    command = argv[0].encode("ascii")
    rc_text = end.get("rc")
    status = end.get("status")
    duration = end.get("duration_ms")
    errno = end.get("errno")
    if not all(isinstance(item, str) and item for item in (rc_text, status, duration, errno)):
        return False
    if kind == b"done":
        if rc_text != "0" or status != "ok" or errno != "0":
            return False
        return text == command + b" (" + duration.encode("ascii") + b"ms)"
    if kind == b"busy":
        return (
            rc_text == "-16"
            and status == "busy"
            and errno == "16"
            and duration == "0"
            and text in _PROTOCOL_BUSY_TEXTS
        )
    if kind != b"err":
        return False
    with_errno = _PROTOCOL_ERR_WITH_ERRNO_RE.fullmatch(text)
    if with_errno is not None:
        try:
            errno_value = int(errno, 10)
        except (TypeError, ValueError):
            return False
        expected_message = _PROTOCOL_ERRNO_MESSAGES.get(errno_value)
        return (
            with_errno.group("cmd") == command
            and with_errno.group("rc").decode("ascii") == rc_text
            and with_errno.group("errno").decode("ascii") == errno
            and with_errno.group("duration").decode("ascii") == duration
            and int(rc_text, 10) < 0
            and expected_message is not None
            and with_errno.group("message") == expected_message
            and status == "error"
        )
    without_errno = _PROTOCOL_ERR_NO_ERRNO_RE.fullmatch(text)
    if without_errno is None:
        return False
    return (
        without_errno.group("cmd") == command
        and without_errno.group("rc").decode("ascii") == rc_text
        and without_errno.group("duration").decode("ascii") == duration
        and rc_text not in {"0", "-0"}
        and int(rc_text, 10) > 0
        and errno == "0"
        and status == "error"
    )


def is_transport_no_value_payload(payload: object) -> bool:
    """Return whether retained post-BEGIN bytes can only be run dispatch.

    The native ``run_console_child`` wrapper writes the PID banner before it
    waits for the child.  A bridge cutoff may split that banner at any byte,
    so every byte-prefix of one canonical positive-PID banner is admissible.
    Once the banner's newline is complete, no further byte is admissible.
    Empty bytes are also valid (the cutoff happened immediately after BEGIN).
    Child output, shell result lines, wait/fork diagnostics, A90R data, and
    malformed/zero/leading-zero PIDs are never no-value evidence.
    """

    if not isinstance(payload, bytes) or b"\x00" in payload:
        return False
    if payload == b"":
        return True

    # A prefix ending before the PID prefix is unambiguously a prefix of the
    # native banner.  This intentionally accepts split points such as ``r``
    # and ``run: pid=`` while still rejecting a different first byte.
    if len(payload) <= len(_PARTIAL_RUN_PREFIX):
        return payload == _PARTIAL_RUN_PREFIX[: len(payload)]
    if not payload.startswith(_PARTIAL_RUN_PREFIX):
        return False

    rest = payload[len(_PARTIAL_RUN_PREFIX) :]
    digit_count = 0
    while digit_count < len(rest) and rest[digit_count] in b"0123456789":
        digit_count += 1
    if digit_count == 0 or rest[0] == ord("0"):
        return False
    # A cutoff anywhere inside the positive decimal PID remains a valid
    # prefix; the next byte can still extend the PID or start the suffix.
    if digit_count == len(rest):
        return True

    suffix = rest[digit_count:]
    if len(suffix) <= len(_PARTIAL_RUN_SUFFIX):
        return _PARTIAL_RUN_SUFFIX.startswith(suffix)
    if not suffix.startswith(_PARTIAL_RUN_SUFFIX):
        return False
    terminal = suffix[len(_PARTIAL_RUN_SUFFIX) :]
    # The terminal itself may be cut between CR and LF.  Any byte after a
    # complete LF/CRLF is forbidden, preventing hidden completion output.
    return terminal in (b"", b"\n", b"\r", b"\r\n")
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
MAX_PARTIAL_EVIDENCE_BYTES = 1024 * 1024
LOCAL_TRANSPORT_MODULE = "tools.a90_pa28_live"
LOCAL_TRANSPORT_SOURCE = "tools/a90_pa28_live.py"
LOCAL_TRANSPORT_SOURCE_SHA256 = (
    "0f50a20453f00a6f647d52cc2c3cd10ba52f8869d6b9264d5b9c47671197bc66"
)
LOCAL_TRANSPORT_SOURCE_SIZE = 150104
SOC_ID = "339"  # Qualcomm SM8150 (the exact A90 sysfs value).
EXPECTED_SOC_ID = SOC_ID

CONTROL_SHA256 = (
    "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247"
)
READ_SHA256 = (
    "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed"
)
ROLLBACK_SHA256 = (
    "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb"
)
EXPECTED_CANDIDATE_HASHES = {
    MODE_CONTROL: CONTROL_SHA256,
    MODE_READ: READ_SHA256,
}
FLASH_EXPECTED_HASHES = {
    **EXPECTED_CANDIDATE_HASHES,
    "rollback": ROLLBACK_SHA256,
}
FLASH_REMOTE_STAGING = {
    MODE_CONTROL: "/tmp/sdm855-remapper-boot.img",
    MODE_READ: "/tmp/sdm855-remapper-boot-read.img",
    "rollback": "/tmp/sdm855-remapper-boot-rollback.img",
}
EXPECTED_HASHES = EXPECTED_CANDIDATE_HASHES
DEFAULT_CANDIDATES = {
    MODE_CONTROL: REPO_ROOT
    / "evidence/private/verification-024-remapper-build-20260827-01/control/"
    / "boot_linux_inline_remapper_control_v1.img",
    MODE_READ: REPO_ROOT
    / "evidence/private/verification-024-remapper-build-20260827-01/read/"
    / "boot_linux_inline_remapper_read_v1.img",
}

SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
KEY_RE = re.compile(r"[A-Za-z0-9_.:-]+\Z")
# Linux command lines legitimately contain these three flag-only tokens on
# the exact retained A90 V2321 boot.  Other flag-only/malformed tokens are
# rejected so a truncated or merged cmdline cannot satisfy the identity gate.
KNOWN_BARE_FLAGS = frozenset({"skip_initramfs", "rootwait", "ro"})
SELFTEST_RE = re.compile(
    rb"(?m)^selftest:\s+pass=(?P<passed>[0-9]+)\s+"
    rb"warn=(?P<warn>[0-9]+)\s+fail=(?P<fail>[0-9]+)\s+"
    rb"duration=(?P<duration>[0-9]+)ms\s+entries=(?P<entries>[0-9]+)\s*$"
)
V024_DISPLAY_RE = re.compile(
    r"display: [0-9]+x[0-9]+"
    r"(?: connector=[0-9]+)?(?: crtc=[0-9]+)?(?: fb=[0-9]+)?\Z"
)
MAX_FLASH_JOURNAL_BYTES = 256 * 1024
MAX_TIMEOUT_SEC = 120.0

CONTROL_R2_PRECLAIM_SCHEMA = "sdm855-a90-inline-remapper-mid-journal-v1"
CONTROL_R2_PRECLAIM_STATUS = "PREDECESSOR_VALIDATION_PENDING"
CONTROL_R2_PREDECESSOR_CAPSULE_SCHEMA = (
    "sdm855-a90-v024-control-predecessor-final-capsule-v1"
)
CONTROL_R2_PREDECESSOR_CAPSULE_SHA256 = (
    "56d233030e1c970b486721b21293a91a154bdc5ebe0ae811b36473457648df15"
)
CONTROL_R2_PREDECESSOR_CAPSULE_SIZE = 4924
CONTROL_R2_HISTORICAL_PINS_POLICY = (
    "historical_predecessor_capsule_bound; current_r2_source_provenance_required_before_live"
)


class ProbeError(RuntimeError):
    """A failure of the exact DMID probe/evidence contract."""


class OperationReturnedError(ProbeError):
    """The fixed op returned a complete frame, but its result was malformed."""

    def __init__(
        self,
        message: str,
        *,
        frame_returned: bool = True,
        frame: Any | None = None,
        partial: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.frame_returned = frame_returned
        # Keep the returned frame/transport evidence attached to the typed
        # error.  ``collect`` must be able to publish the malformed result as
        # a returned INCIDENT without treating it as a no-value transport
        # failure or losing the retained BEGIN/END proof.
        if frame is not None:
            self.partial_frame = frame
        if partial is not None:
            self.partial = partial


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def frame_record(evidence_id: str, argv: Sequence[str], frame: Any) -> dict[str, object]:
    payload = getattr(frame, "payload", b"")
    transcript = getattr(frame, "transcript", b"")
    begin = getattr(frame, "begin", {})
    end = getattr(frame, "end", {})
    return {
        "evidence_id": evidence_id,
        "argv": list(argv),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": sha256_bytes(payload),
        "payload_size": len(payload),
        # Keep the complete protocol exchange private so downstream
        # finalization can independently bind BEGIN/END and payload instead
        # of trusting a measurement summary.  The public projection remains
        # redacted elsewhere.
        "transcript_base64": base64.b64encode(transcript).decode("ascii"),
        "transcript_sha256": sha256_bytes(transcript),
        "transcript_size": len(transcript),
        "begin": dict(begin) if isinstance(begin, Mapping) else {},
        "end": dict(end) if isinstance(end, Mapping) else {},
    }


def parse_single_decimal(payload: bytes) -> int:
    text = payload.decode("ascii", errors="strict").strip()
    if re.fullmatch(r"[0-9]+", text) is None:
        raise ProbeError(f"expected one decimal integer, got {text!r}")
    return int(text, 10)


def parse_toybox_wc_count(payload: bytes, expected_path: str) -> int:
    """Parse Toybox ``wc -c FILE`` as exactly ``COUNT FILE``."""

    body = parse_toybox_payload(payload, "toybox wc -c")
    pattern = rb"(0|[1-9][0-9]*) " + re.escape(expected_path.encode("ascii"))
    match = re.fullmatch(pattern, body)
    if match is None:
        raise ProbeError(
            f"toybox wc output is not exact COUNT {expected_path}: {body!r}"
        )
    return int(match.group(1), 10)


def parse_toybox_payload(payload: bytes, label: str) -> bytes:
    """Strip one closed native ``run`` wrapper and require exit 0.

    The native producer emits one positive-PID banner, zero or more output
    lines, and one final ``[exit 0]`` line.  Only LF/CRLF line endings are
    accepted, with at most one terminal line ending.  Empty leading,
    trailing, or intervening lines are rejected so an empty-output command
    cannot be confused with a wrapper carrying hidden bytes.
    """

    if not isinstance(payload, bytes):
        raise ProbeError(f"{label} payload is not bytes")
    if b"\r" in payload.replace(b"\r\n", b""):
        raise ProbeError(f"{label} contains a bare CR")
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized.endswith(b"\n"):
        normalized = normalized[:-1]
    if not normalized or normalized.endswith(b"\n"):
        raise ProbeError(f"{label} has more than one terminal line ending")
    lines = normalized.split(b"\n")
    if any(not line for line in lines):
        raise ProbeError(f"{label} has a leading, trailing, or empty line")
    if not TOYBOX_RUN_RE.fullmatch(lines[0]):
        raise ProbeError(f"{label} lacks the exact first child run banner")
    if lines[-1] != b"[exit 0]":
        raise ProbeError(f"{label} lacks the exact final child exit 0")
    if sum(bool(TOYBOX_RUN_RE.fullmatch(line)) for line in lines) != 1:
        raise ProbeError(f"{label} has a duplicate child run banner")
    if sum(bool(TOYBOX_EXIT_RE.fullmatch(line)) for line in lines) != 1:
        raise ProbeError(f"{label} has a duplicate or nonzero child exit")
    return b"\n".join(lines[1:-1])


def require_empty_toybox_payload(payload: bytes, label: str) -> None:
    """Require a successful toybox wrapper with no command stdout body."""

    if parse_toybox_payload(payload, label) != b"":
        raise ProbeError(f"{label} returned an unexpected command body")


def parse_fixed_op_result(payload: bytes) -> tuple[int, str]:
    """Parse exactly one framed ``A90R<hex>`` result line.

    The child command is transported inside the native ``run`` wrapper.  The
    wrapper is stripped first, then the resulting body must be one complete
    A90R line.  In particular, a match embedded in ``A90Rc071garbage`` or
    alongside a second line is not a measurement.
    """

    try:
        body = parse_toybox_payload(payload, "fixed op 4")
    except ProbeError as exc:
        # A payload reaching this parser came from a completed exchange.  A
        # malformed child wrapper is therefore a returned incident just like
        # a malformed A90R line, never a transport no-value observation.
        raise OperationReturnedError(
            f"fixed op 4 result framing is malformed: {exc}"
        ) from exc
    normalized = body.replace(b"\r\n", b"\n")
    lines = normalized.splitlines()
    if len(lines) != 1:
        raise OperationReturnedError(
            f"fixed op 4 body has {len(lines)} records, expected exactly one"
        )
    match = FIXED_OP_A90R_LINE_RE.fullmatch(lines[0])
    if match is None:
        raise OperationReturnedError(
            f"fixed op 4 returned a malformed A90R record: {lines[0]!r}"
        )
    value = int(match.group("value"), 16)
    record = lines[0].decode("ascii")
    if record != f"A90R{value:x}":
        raise OperationReturnedError(
            f"fixed op 4 A90R record is not canonical: {record!r}"
        )
    return value, record


def build_fixed_op_buffer() -> bytes:
    """Return the fixed 0x58-byte op-4/all-zero command buffer."""

    buffer = bytearray(FIXED_OP_BUFFER_SIZE)
    struct.pack_into("<Q", buffer, 0, FIXED_OP_MAGIC)
    buffer[8] = OP_FIXED_READ
    return bytes(buffer)


def fixed_op_argv() -> tuple[str, ...]:
    """Build the exact single BusyBox shell argv used for op 4."""

    escaped = "".join(f"\\{byte:03o}" for byte in build_fixed_op_buffer())
    shell = (
        # Keep the kernel log intact.  The pre-op snapshot is a cursor: the
        # post-op snapshot must retain the exact prefix, otherwise a ring
        # wrap or an intervening writer makes the result unknowable.
        "set -eu; "
        "before_log=$(dmesg 2>/dev/null) || exit 97; "
        "before_count=0; "
        "if [ -n \"$before_log\" ]; then "
        "before_count=$(printf '%s\\n' \"$before_log\" | wc -l | tr -d '[:space:]'); "
        "fi; "
        "case \"$before_count\" in ''|*[!0-9]*) exit 97;; esac; "
        f"printf '{escaped}' > {FIXED_OP_NODE}; "
        "after_log=$(dmesg 2>/dev/null) || exit 97; "
        "after_count=0; "
        "if [ -n \"$after_log\" ]; then "
        "after_count=$(printf '%s\\n' \"$after_log\" | wc -l | tr -d '[:space:]'); "
        "fi; "
        "case \"$after_count\" in ''|*[!0-9]*) exit 97;; esac; "
        "[ \"$after_count\" -ge \"$before_count\" ] || exit 97; "
        "if [ \"$before_count\" -gt 0 ]; then "
        "prefix=$(printf '%s\\n' \"$after_log\" | head -n \"$before_count\"); "
        "[ \"$prefix\" = \"$before_log\" ] || exit 97; "
        "fi; "
        "printf '%s\\n' \"$after_log\" | "
        "tail -n +$((before_count + 1)) | "
        f"tail -n {FIXED_OP_DMESG_TAIL} | grep -a 'A90R'"
    )
    return ("run", "/bin/busybox", "sh", "-c", shell)


def _transport_failure_returned_fixed_op(
    exc: BaseException, argv: Sequence[str]
) -> bool:
    """Return whether a typed transport error retained this op's END frame.

    ``TransportFailure`` is normally ambiguous because the bridge may have
    dropped before the operation's terminal frame.  The local transport
    retains a ``PartialEvidence`` object when it did see a complete frame but
    could not validate it (for example, an invalid ``rc`` token).  The raw
    transcript is authoritative: require one complete protocol frame, bind
    its parsed BEGIN/END mappings to the retained metadata, and validate the
    fixed command surface.  ``rc`` remains deliberately unparsed so malformed
    return codes still count as returned incidents.
    """

    typed_failure = getattr(native_transport, "TransportFailure", None)
    partial_type = getattr(native_transport, "PartialEvidence", None)
    if (
        not isinstance(typed_failure, type)
        or type(exc) is not typed_failure
        or not isinstance(partial_type, type)
    ):
        return False
    partial = getattr(exc, "partial", None)
    if type(partial) is not partial_type:
        return False
    if tuple(argv) != fixed_op_argv():
        return False
    transcript = getattr(partial, "transcript", None)
    begin = getattr(partial, "begin", None)
    end = getattr(partial, "end", None)
    if not isinstance(begin, Mapping):
        return False
    if not isinstance(transcript, bytes) or len(transcript) > MAX_PARTIAL_EVIDENCE_BYTES:
        return False
    begin_matches = list(BEGIN_RE.finditer(transcript))
    end_matches = list(END_RE.finditer(transcript))
    if (
        transcript.count(b"A90P1 BEGIN") != len(begin_matches)
        or transcript.count(b"A90P1 END") != len(end_matches)
        or len(begin_matches) != 1
        or len(end_matches) != 1
    ):
        return False
    begin_match = begin_matches[0]
    end_match = end_matches[0]
    if end_match.start() <= begin_match.end():
        return False
    try:
        parsed_begin = parse_fields(begin_match.group("fields"))
        parsed_end = parse_fields(end_match.group("fields"))
    except (TypeError, UnicodeDecodeError, ValueError):
        return False
    if parsed_begin != dict(begin):
        return False
    # A typed transport can retain a complete BEGIN/END transcript even when
    # parsing the outer result line fails.  In that case ``PartialEvidence``
    # intentionally leaves ``end`` unset; the raw protocol END is still the
    # independent proof that the device returned.  If ``end`` is present,
    # bind it to the parsed END exactly.
    if end is not None and (not isinstance(end, Mapping) or parsed_end != dict(end)):
        return False
    partial_payload = getattr(partial, "payload", None)
    if not isinstance(partial_payload, bytes):
        return False
    try:
        parsed_frame = parse_last_frame(transcript, argv[0])
    except (TypeError, UnicodeDecodeError, ValueError):
        parsed_frame = None
    if parsed_frame is not None:
        if parsed_frame.begin != dict(begin) or parsed_frame.end != parsed_end:
            return False
        if parsed_frame.payload != partial_payload:
            return False
    elif end is not None:
        # A retained metadata END normally comes from a successfully parsed
        # frame.  Do not accept a contradictory transcript/parser shape.
        return False
    elif partial_payload != transcript[begin_match.end() :]:
        # ``_partial_from_transcript`` derives payload as the complete raw
        # suffix after BEGIN when result parsing fails.  Preserve that binding
        # so a detached payload cannot manufacture a returned classification.
        return False
    expected_command = argv[0] if argv else None
    sequence = begin.get("seq")
    if (
        expected_command is None
        or begin.get("cmd") != expected_command
        or parsed_end.get("cmd") != expected_command
        or not isinstance(sequence, str)
        or re.fullmatch(r"[0-9]+", sequence) is None
        or (len(sequence) > 1 and sequence.startswith("0"))
        or parsed_end.get("seq") != sequence
        or set(begin) != {"seq", "cmd", "argc", "flags"}
        or begin.get("argc") != str(len(argv))
        or begin.get("flags") != protocol_flags_for_argv(argv)
        or set(parsed_end)
        != {"seq", "cmd", "rc", "errno", "duration_ms", "flags", "status"}
        or parsed_end.get("flags") != protocol_flags_for_argv(argv)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)", str(parsed_end.get("errno"))) is None
        or re.fullmatch(r"(?:0|[1-9][0-9]*)", str(parsed_end.get("duration_ms"))) is None
    ):
        return False
    return True


def validate_complete_frame(
    frame: Any,
    argv: Sequence[str],
    label: str = "A90P1 frame",
    *,
    allow_stophud_busy: bool = False,
    validate_result_semantics: bool = True,
) -> Any:
    """Validate one complete returned A90P1 exchange before it is trusted.

    Every device exchange that can authorize a later command uses this
    validator.  It binds the exact command-derived flags, canonical BEGIN/
    END mappings, transcript framing, and payload bytes.  Fixed op 4 uses
    ``validate_result_semantics=False`` because a complete but malformed
    returned rc/status is still a device return that must enter the mandatory
    panic restore path; its caller performs the returned-result classification
    separately.
    """

    expected_argv = tuple(argv)
    if not expected_argv or any(not isinstance(item, str) for item in expected_argv):
        raise ProbeError(f"{label} argv is not exact")
    expected_flags = protocol_flags_for_argv(expected_argv)
    if expected_flags is None:
        raise ProbeError(f"{label} command is outside the fixed protocol table")
    begin = getattr(frame, "begin", None)
    end = getattr(frame, "end", None)
    payload = getattr(frame, "payload", None)
    transcript = getattr(frame, "transcript", None)
    if (
        not isinstance(begin, Mapping)
        or not isinstance(end, Mapping)
        or not isinstance(payload, bytes)
        or not isinstance(transcript, bytes)
        or len(transcript) > MAX_PARTIAL_EVIDENCE_BYTES
        or len(payload) > MAX_PARTIAL_EVIDENCE_BYTES
    ):
        raise ProbeError(f"{label} complete frame fields are not bounded")
    if expected_argv == STOPHUD_ARGV:
        try:
            validate_stophud_evidence_sizes(payload, transcript)
        except BaseException as exc:
            raise ProbeError(f"{label} stophud evidence size is not bounded") from exc
    begin_matches = list(BEGIN_RE.finditer(transcript))
    end_matches = list(END_RE.finditer(transcript))
    if (
        transcript.count(b"A90P1 BEGIN") != len(begin_matches)
        or transcript.count(b"A90P1 END") != len(end_matches)
        or len(begin_matches) != 1
        or len(end_matches) != 1
        or end_matches[0].start() <= begin_matches[0].end()
    ):
        raise ProbeError(f"{label} protocol frame count/order is not exact")
    try:
        parsed_begin = parse_fields(begin_matches[0].group("fields"))
        parsed_end = parse_fields(end_matches[0].group("fields"))
    except (TypeError, UnicodeDecodeError, ValueError) as exc:
        raise ProbeError(f"{label} protocol fields are malformed") from exc
    if (
        set(begin) != {"seq", "cmd", "argc", "flags"}
        or set(end) != {"seq", "cmd", "rc", "errno", "duration_ms", "flags", "status"}
        or dict(begin) != parsed_begin
        or dict(end) != parsed_end
        or begin.get("cmd") != expected_argv[0]
        or end.get("cmd") != expected_argv[0]
        or begin.get("seq") != end.get("seq")
        or not isinstance(begin.get("seq"), str)
        or re.fullmatch(r"[0-9]+", begin.get("seq", "")) is None
        or (len(begin["seq"]) > 1 and begin["seq"].startswith("0"))
        or begin.get("argc") != str(len(expected_argv))
        or begin.get("flags") != expected_flags
        or end.get("flags") != expected_flags
    ):
        raise ProbeError(f"{label} command/sequence/argc/flags are not exact")

    rc_text = end.get("rc")
    errno_text = end.get("errno")
    duration_text = end.get("duration_ms")
    status = end.get("status")
    if not all(isinstance(item, str) and item for item in (rc_text, errno_text, duration_text, status)):
        raise ProbeError(f"{label} END result fields are not bounded text")
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", rc_text) is None or rc_text == "-0":
        raise ProbeError(f"{label} rc is not canonical decimal")
    if re.fullmatch(r"(?:0|[1-9][0-9]*)", errno_text) is None:
        raise ProbeError(f"{label} errno is not canonical decimal")
    if re.fullmatch(r"(?:0|[1-9][0-9]*)", duration_text) is None:
        raise ProbeError(f"{label} duration_ms is not canonical decimal")
    rc = int(rc_text, 10)
    expected_errno = -rc if rc < 0 else 0
    if int(errno_text, 10) != expected_errno:
        raise ProbeError(f"{label} errno does not match rc")
    if validate_result_semantics:
        if rc == 0:
            expected_status = "ok"
        elif allow_stophud_busy and rc == -16:
            expected_status = "busy"
        else:
            raise ProbeError(f"{label} returned a non-success terminal rc")
        if status != expected_status:
            raise ProbeError(f"{label} status does not match rc")

    try:
        parsed_frame = parse_last_frame(transcript, expected_argv[0])
    except (TypeError, UnicodeDecodeError, ValueError) as exc:
        raise ProbeError(f"{label} transcript is not a complete exchange") from exc
    if (
        parsed_frame.begin != dict(begin)
        or parsed_frame.end != dict(end)
        or parsed_frame.payload != payload
        or parsed_frame.transcript != transcript
    ):
        raise ProbeError(f"{label} payload/transcript binding is not exact")
    if not protocol_terminal_and_tail_valid(
        transcript,
        begin_matches[0],
        end_matches[0],
        expected_argv,
        end,
    ):
        raise ProbeError(f"{label} terminal marker or post-END tail is not exact")
    return frame


def run_fixed_inline_op(
    host: str,
    port: int,
    timeout: float,
    frames: list[dict[str, object]],
) -> tuple[int, dict[str, object]]:
    """Dispatch fixed op 4 once through the local A90P1 ExtendedCommand."""

    argv = fixed_op_argv()
    command = ExtendedCommand("fixed_op_4", argv)
    try:
        frame = exchange(host, port, command, timeout, allow_error=True)
    except BaseException as exc:
        if _transport_failure_returned_fixed_op(exc, argv):
            partial = getattr(exc, "partial", None)
            _record_frame(frames, "fixed_op_4", argv, partial)
            raise OperationReturnedError(
                "fixed op 4 transport retained a complete terminal frame",
                partial=partial,
            ) from exc
        raise
    try:
        # Keep result semantics separate: malformed rc/status is a returned
        # operation and must still receive panic_on_oops restoration.
        validate_complete_frame(
            frame,
            argv,
            "fixed op 4",
            validate_result_semantics=False,
        )
    except ProbeError as exc:
        _record_frame(frames, "fixed_op_4", argv, frame)
        raise OperationReturnedError(
            f"fixed op frame is malformed: {exc}",
            frame=frame,
        ) from exc
    _record_frame(frames, "fixed_op_4", argv, frame)
    try:
        rc = int(frame.end["rc"], 0)
        status = str(frame.end["status"])
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise OperationReturnedError(
            "fixed op frame lacks exact rc/status", frame=frame
        ) from exc
    if rc != 0 or status != "ok":
        raise OperationReturnedError(
            f"fixed op 4 returned an error: rc={rc} status={status!r}",
            frame=frame,
        )
    try:
        value, a90r_record = parse_fixed_op_result(frame.payload)
    except OperationReturnedError as exc:
        # ``parse_fixed_op_result`` already uses the returned-only type for a
        # malformed A90R body; retain the complete frame on that error too.
        if getattr(exc, "partial_frame", None) is None:
            exc.partial_frame = frame
        raise
    except ProbeError as exc:
        # Wrapper errors (including malformed run/exit framing) happen after
        # exchange returned a complete frame, so they are returned incidents,
        # not ambiguous/no-value transport failures.
        raise OperationReturnedError(
            f"fixed op 4 result framing is malformed: {exc}", frame=frame
        ) from exc
    measurement = {
        "argv": list(argv),
        "buffer_size": FIXED_OP_BUFFER_SIZE,
        "buffer_sha256": sha256_bytes(build_fixed_op_buffer()),
        "magic": f"0x{FIXED_OP_MAGIC:016x}",
        "op": OP_FIXED_READ,
        "args": [],
        "rc": rc,
        "status": status,
        "value": f"0x{value:016x}",
        "a90r_record": a90r_record,
    }
    return value, measurement


def _write_panic_on_oops(
    host: str,
    port: int,
    timeout: float,
    value: int,
    frames: list[dict[str, object]],
) -> None:
    if value not in (0, 1):
        raise ProbeError("panic_on_oops write is outside exact 0/1 values")
    argv = ("writefile", "/proc/sys/kernel/panic_on_oops", str(value))
    command = ExtendedCommand(f"panic_set_{value}", argv)
    frame = _attest_one(host, port, timeout, command, frames)
    if getattr(frame, "payload", None) != b"":
        raise ProbeError(f"panic_set_{value} returned unexpected payload")


def sha256_file(path: Path) -> str:
    return _stable_file_digest(path)[1]


def _validate_local_transport() -> dict[str, object]:
    """Prove the imported bridge implementation is the pinned local source."""

    source_lexical = REPO_ROOT / LOCAL_TRANSPORT_SOURCE
    source_path = source_lexical.resolve()
    module_file_obj = getattr(native_transport, "__file__", None)
    if not isinstance(module_file_obj, str):
        raise ProbeError("local A90 transport has no source file")
    module_path = Path(module_file_obj).resolve()
    if module_path != source_path:
        raise ProbeError(
            f"local A90 transport module path is not exact: {module_path} != {source_path}"
        )
    # Pass the lexical path to the stable reader so a source symlink cannot be
    # normalized away before its no-follow parent/leaf checks.
    source_size, source_hash = _stable_file_digest(source_lexical)
    if source_size != LOCAL_TRANSPORT_SOURCE_SIZE:
        raise ProbeError(
            f"local A90 transport source size is not exact: {source_size} != "
            f"{LOCAL_TRANSPORT_SOURCE_SIZE}"
        )
    if source_hash != LOCAL_TRANSPORT_SOURCE_SHA256:
        raise ProbeError(
            "local A90 transport source SHA-256 mismatch: "
            f"{source_hash} != {LOCAL_TRANSPORT_SOURCE_SHA256}"
        )
    return {
        "module": LOCAL_TRANSPORT_MODULE,
        "source": LOCAL_TRANSPORT_SOURCE,
        "source_path": str(source_path),
        "source_size": source_size,
        "source_sha256": source_hash,
        "module_path": str(module_path),
        "verified": True,
    }


def _reject_symlink_components(path: Path, label: str = "candidate") -> None:
    """Reject a leaf or parent symlink before opening a candidate image."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    if path.is_symlink():
        raise ProbeError(f"{label} must not be a symlink: {path}")
    cursor = lexical.parent
    anchor = Path(cursor.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise ProbeError(f"{label} parent component must not be a symlink: {cursor}")
        if cursor == anchor:
            break
        cursor = cursor.parent


def _stable_file_digest(path: Path) -> tuple[int, str]:
    """Hash one stable regular file through one no-follow descriptor."""

    _reject_symlink_components(path)
    try:
        fd = _open_regular_nofollow(path)
    except OSError as exc:
        raise ProbeError(f"candidate is unavailable: {path}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ProbeError(f"candidate is not a regular file: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise ProbeError(f"candidate changed while being read: {path}")
        return after.st_size, digest.hexdigest()
    finally:
        os.close(fd)


def _open_regular_nofollow(path: Path) -> int:
    """Walk parent directories with ``O_NOFOLLOW`` before opening the leaf."""

    absolute = Path(os.path.abspath(path))
    components = absolute.parts
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    parent_fd = os.open(components[0], directory_flags)
    try:
        for component in components[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        leaf_flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            leaf_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            leaf_flags |= os.O_NOFOLLOW
        return os.open(components[-1], leaf_flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    """Durably replace a journal revision without following a leaf symlink."""

    data = json_bytes(value)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ProbeError(f"journal temporary already exists: {temporary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
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


def _exclusive_json(path: Path, value: object, mode: int = 0o600) -> bytes:
    """Create one durable JSON record with an O_EXCL final-path lock.

    The first journal revision and the semantic op claim must not use an
    ``exists()`` check followed by ``os.replace``: two owners can otherwise
    both pass the precheck and each publish a different intent.  O_EXCL on
    the final inode is the arbitration primitive for those one-way records.
    """

    data = json_bytes(value)
    _reject_symlink_components(path.parent, "exclusive JSON")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise ProbeError(f"exclusive JSON already exists; replay forbidden: {path}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProbeError(f"short write while creating {path}")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return data


def _semantic_claim(
    root: Path,
    mode: str,
    candidate_sha256: str,
    candidate_size: int,
    boot_id: str,
    experiment_id: str,
) -> tuple[Path, bytes, str]:
    """Acquire the one-way same-boot/mode/candidate dispatch claim."""

    key = (
        f"verification-024-inline-op\0{mode}\0{candidate_sha256}\0"
        f"{candidate_size}\0{boot_id}"
    ).encode("ascii")
    key_sha256 = sha256_bytes(key)
    claim_path = (
        root
        / "evidence/private"
        / f"verification-024-inline-op-{key_sha256}.claim.json"
    )
    claim = {
        "schema": "sdm855-a90-inline-op-semantic-claim-v1",
        "mode": mode,
        "candidate_sha256": candidate_sha256,
        "candidate_size": candidate_size,
        "boot_id": boot_id,
        "boot_id_sha256": sha256_bytes(boot_id.encode("ascii")),
        "key_sha256": key_sha256,
        "claimed_by_experiment_id": experiment_id,
        "effect_replayed": False,
    }
    claim_bytes = _exclusive_json(claim_path, claim, 0o600)
    return claim_path, claim_bytes, key_sha256


def _fixed_control_manifest_path(root: Path) -> Path:
    return root / "evidence" / "manifests" / f"{CONTROL_EXPERIMENT_ID}.manifest.json"


def _control_r2_preclaim() -> dict[str, object]:
    """Return the file-only R2 predecessor-validation intent.

    This object is built solely from fixed constants.  It is written before
    any candidate, transport, flash, predecessor, bridge or device evidence
    is read, so a failed predecessor check leaves a durable no-replay owner.
    """

    return {
        "schema": CONTROL_R2_PRECLAIM_SCHEMA,
        "status": CONTROL_R2_PRECLAIM_STATUS,
        "experiment_id": CONTROL_EXPERIMENT_ID,
        "predecessor_experiment_id": CONTROL_PREDECESSOR_EXPERIMENT_ID,
        "mode": MODE_CONTROL,
        "replay_safe": False,
        "predecessor_capsule": {
            "schema": CONTROL_R2_PREDECESSOR_CAPSULE_SCHEMA,
            "sha256": CONTROL_R2_PREDECESSOR_CAPSULE_SHA256,
            "size": CONTROL_R2_PREDECESSOR_CAPSULE_SIZE,
            "historical_pins_policy": CONTROL_R2_HISTORICAL_PINS_POLICY,
        },
    }


def _load_control_r2_predecessor() -> tuple[dict[str, object], bytes, dict[str, object]]:
    """Load and bind the exact A2b capsule after the durable preclaim."""

    capsule = control_retry.build_predecessor_capsule()
    if type(capsule) is not dict or set(capsule) != {
        "schema",
        "semantic_capsule",
        "historical_git_verification",
    }:
        raise ProbeError("predecessor capsule schema is not exact")
    if capsule.get("schema") != CONTROL_R2_PREDECESSOR_CAPSULE_SCHEMA:
        raise ProbeError("predecessor capsule schema is not the fixed final schema")
    capsule_bytes = control_retry.canonical_capsule_bytes(capsule)
    if type(capsule_bytes) is not bytes:
        raise ProbeError("predecessor capsule bytes are not exact")
    descriptor = {
        "schema": CONTROL_R2_PREDECESSOR_CAPSULE_SCHEMA,
        "sha256": sha256_bytes(capsule_bytes),
        "size": len(capsule_bytes),
    }
    if descriptor["sha256"] != CONTROL_R2_PREDECESSOR_CAPSULE_SHA256:
        raise ProbeError("predecessor capsule hash is not the fixed final hash")
    if descriptor["size"] != CONTROL_R2_PREDECESSOR_CAPSULE_SIZE:
        raise ProbeError("predecessor capsule size is not the fixed final size")
    return capsule, capsule_bytes, descriptor


def _fixed_flash_journal_path(root: Path, mode: str) -> Path:
    if mode not in MODES:
        raise ProbeError(f"unsupported mode: {mode!r}")
    return (
        root
        / "evidence"
        / "private"
        / f"{FLASH_JOURNAL_PREFIX}{mode}.journal.json"
    )


def _fixed_selector_path(
    args: argparse.Namespace,
    name: str,
    expected: Path,
    *,
    root: Path,
    allow_absent: bool = True,
) -> None:
    """Reject injected path selectors unless they are the exact fixed path."""

    if not hasattr(args, name):
        if allow_absent:
            return
        raise ProbeError(f"{name} selector is required")
    supplied = getattr(args, name)
    if supplied is None:
        raise ProbeError(f"{name} selector is disabled; fixed producer path required")
    try:
        supplied_path = Path(supplied)
        _reject_symlink_components(supplied_path, f"{name} selector")
        resolved = supplied_path.resolve()
    except (TypeError, ValueError, OSError) as exc:
        raise ProbeError(f"{name} selector is not the fixed producer path") from exc
    if resolved != expected.resolve():
        raise ProbeError(f"{name} selector is not the fixed producer path")


def _fixed_output_root(args: argparse.Namespace) -> Path:
    """Resolve only the repository-owned evidence root.

    The parser no longer exposes ``--output-root``.  Namespace callers may
    still inject it, so an injected value is accepted only when it resolves to
    the module's fixed repository root (which tests may patch explicitly).
    """

    _reject_symlink_components(REPO_ROOT, "output root")
    expected = REPO_ROOT.resolve()
    for item in (
        expected,
        expected / "evidence",
        expected / "evidence" / "private",
        expected / "evidence" / "manifests",
    ):
        if item.is_symlink():
            raise ProbeError(f"fixed evidence root component must not be a symlink: {item}")
    if hasattr(args, "output_root"):
        supplied = getattr(args, "output_root")
        if supplied is None:
            raise ProbeError("output root selector is disabled; root is fixed to REPO_ROOT")
        try:
            supplied_path = Path(supplied)
            _reject_symlink_components(supplied_path, "output root")
            if supplied_path.resolve() != expected:
                raise ProbeError("output root selector is disabled; root is fixed to REPO_ROOT")
        except ProbeError:
            raise
        except (TypeError, ValueError, OSError) as exc:
            raise ProbeError("output root selector is disabled; root is fixed to REPO_ROOT") from exc
    return expected


def parse_cmdline(payload: bytes) -> dict[str, str]:
    """Parse every cmdline token and reject malformed or duplicate keys."""

    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProbeError("target cmdline is not ASCII") from exc
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if (
        not text
        or text[0].isspace()
        or text[-1].isspace()
        or "\x00" in text
    ):
        raise ProbeError("target cmdline framing is not exact")
    if any(char.isspace() and char != " " for char in text):
        raise ProbeError("target cmdline contains non-space whitespace")
    parsed: dict[str, str] = {}
    for token in (item for item in text.split(" ") if item):
        if "=" not in token:
            if token not in KNOWN_BARE_FLAGS:
                raise ProbeError(f"malformed cmdline token: {token!r}")
            if token in parsed:
                raise ProbeError(f"duplicate cmdline key: {token}")
            parsed[token] = ""
            continue
        key, value = token.split("=", 1)
        if (
            KEY_RE.fullmatch(key) is None
            or not value
            or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
        ):
            raise ProbeError(f"malformed cmdline key/value: {token!r}")
        if key in parsed:
            raise ProbeError(f"duplicate cmdline key: {key}")
        parsed[key] = value
    return parsed


def _one_line(payload: bytes, label: str) -> str:
    if not isinstance(payload, bytes):
        raise ProbeError(f"{label} is not bytes")
    if b"\r" in payload.replace(b"\r\n", b""):
        raise ProbeError(f"{label} contains a bare CR")
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProbeError(f"{label} is not ASCII") from exc
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if (
        not text
        or "\n" in text
        or "\r" in text
        or "\x00" in text
        or text != text.strip()
    ):
        raise ProbeError(f"{label} is not one bounded text value")
    return text


def _parse_canonical_devnum(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> str:
    """Validate one exact unsigned decimal device-number field."""

    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise ProbeError(f"{label} is not canonical unsigned decimal")
    number = int(value, 10)
    if not minimum <= number <= maximum:
        raise ProbeError(f"{label} is outside the bounded device-number range")
    return value


def _parse_stat_identity(
    payload: bytes,
    expected_major: str,
    expected_minor: str,
) -> dict[str, str]:
    """Parse the native ``stat`` response for the temporary block node.

    V2321's ``cmd_stat`` intentionally emits the mode/uid/gid/size fields on
    one line and, for block or character nodes, emits ``rdev`` on the next
    line.  It does not emit a ``type=block`` token.  Keep the syntax strict:
    exactly one four-field metadata line followed by exactly one rdev line,
    with no duplicate/unknown fields and the exact major/minor pair parsed from
    the fixed sysfs uevent immediately before node creation.
    """

    if type(payload) is not bytes:
        raise ProbeError("temporary node stat is not bytes")
    if b"\x00" in payload:
        raise ProbeError("temporary node stat contains NUL")
    try:
        payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProbeError("temporary node stat is not ASCII") from exc

    # Normalize only CRLF pairs.  The live native response is CRLF between
    # the two lines with no terminal newline; retained LF/CRLF fixtures may
    # carry one terminal newline.  Comparing the complete normalized bytes
    # keeps the grammar closed: bare CR, empty/extra lines, duplicate or
    # unknown fields, spacing changes, and rdev prefix/suffix lookalikes are
    # all rejected before producing a semantic dictionary.
    normalized = payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise ProbeError("temporary node stat contains a bare CR")
    expected_major = _parse_canonical_devnum(
        expected_major, "expected stat major", BOOT_MAJOR_MIN, BOOT_MAJOR_MAX
    )
    expected_minor = _parse_canonical_devnum(
        expected_minor, "expected stat minor", BOOT_MINOR_MIN, BOOT_MINOR_MAX
    )
    expected_metadata = b"mode=0600 uid=0 gid=0 size=0"
    expected_rdev = f"rdev={expected_major}:{expected_minor}".encode("ascii")
    allowed = {
        expected_metadata + b"\n" + expected_rdev,
        expected_metadata + b"\n" + expected_rdev + b"\n",
    }
    if normalized not in allowed:
        raise ProbeError("temporary node stat record is not exact")
    return {
        "mode": "0600",
        "uid": "0",
        "gid": "0",
        "size": "0",
        "rdev": f"{expected_major}:{expected_minor}",
    }


def _normalise_zero(value: str) -> str:
    if value == "0":
        return "0"
    if re.fullmatch(r"0[xX]0+", value):
        return "0"
    raise ProbeError(f"expected zero value, got {value!r}")


def _parse_exact_sysctl(payload: bytes, expected: str) -> int:
    expected_bytes = expected.encode("ascii")
    if payload not in (expected_bytes + b"\n", expected_bytes + b"\r\n"):
        raise ProbeError(
            f"panic_on_oops output is not exact {expected} with one line ending: {payload!r}"
        )
    return int(expected, 10)


def parse_boot_id(payload: bytes, label: str = "boot_id") -> str:
    """Parse one exact Linux boot UUID for causal evidence binding."""

    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProbeError(f"{label} is not ASCII") from exc
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text or text != text.strip() or "\n" in text or "\r" in text or "\x00" in text:
        raise ProbeError(f"{label} is not one bounded text value")
    if BOOT_ID_RE.fullmatch(text) is None:
        raise ProbeError(f"{label} is not one lowercase boot UUID: {text!r}")
    return text


def parse_version_payload(payload: bytes, label: str = "target version") -> dict[str, str]:
    """Parse the exact V2321 version record used by the finalizer.

    Keep the producer gate closed over line order, optional owner/display
    metadata, and terminal framing.  This prevents a permissive identity
    substring match from authorizing the later attestation and panic write.
    """

    if not isinstance(payload, bytes):
        raise ProbeError(f"{label} is not bytes")
    if b"\r" in payload.replace(b"\r\n", b""):
        raise ProbeError(f"{label} contains a bare CR")
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized.endswith(b"\n"):
        normalized = normalized[:-1]
    if not normalized or b"\x00" in normalized or b"\n\n" in normalized:
        raise ProbeError(f"{label} has empty framing")
    try:
        lines = normalized.decode("ascii", errors="strict").split("\n")
    except UnicodeDecodeError as exc:
        raise ProbeError(f"{label} is not ASCII") from exc
    if any(not line for line in lines):
        raise ProbeError(f"{label} has an empty line")
    expected = [
        f"{EXPECTED_VERSION} ({EXPECTED_RUNTIME_BUILD})",
        f"version: {EXPECTED_RUNTIME} {EXPECTED_BUILD}",
        f"kernel: {EXPECTED_KERNEL}",
    ]
    prefixes = ("A90 Linux init ", "version: ", "kernel: ")
    identity = [line for line in lines if line.startswith(prefixes)]
    if identity != expected:
        raise ProbeError(f"{label} identity lines are missing, conflicting, or reordered")
    if sum(line == "made by device owner" for line in lines) > 1:
        raise ProbeError(f"{label} owner metadata is duplicated")
    display_lines = [line for line in lines if line.startswith("display: ")]
    if len(display_lines) > 1:
        raise ProbeError(f"{label} display metadata is duplicated")
    for line in lines:
        if line in expected or line == "made by device owner":
            continue
        if V024_DISPLAY_RE.fullmatch(line) is None:
            raise ProbeError(f"{label} metadata line is not exact")
    return {
        "runtime_version": EXPECTED_VERSION,
        "runtime_build": EXPECTED_RUNTIME_BUILD,
        "kernel": EXPECTED_KERNEL,
    }


def validate_target(
    version_payload: bytes,
    cmdline_payload: bytes,
    soc_payload: bytes | str | None = None,
) -> dict[str, object]:
    """Require one exact V2321 runtime, DMID cmdline, and SM8150 id."""

    parse_version_payload(version_payload)

    cmdline = parse_cmdline(cmdline_payload)
    expected = {
        "androidboot.em.model": EXPECTED_MODEL,
        "androidboot.bootloader": "A908NKSU5EWA3",
        "androidboot.debug_level": "0x494d",
    }
    for key, expected_value in expected.items():
        if cmdline.get(key) != expected_value:
            raise ProbeError(
                f"target cmdline lacks exact DMID identity {key}={expected_value}"
            )
    force_upload = _normalise_zero(cmdline.get("androidboot.force_upload", ""))
    dump_sink = _normalise_zero(cmdline.get("sec_debug.dump_sink", ""))

    if soc_payload is not None:
        soc = (
            _one_line(soc_payload, "soc_id")
            if isinstance(soc_payload, bytes)
            else str(soc_payload)
        )
        if soc != SOC_ID:
            raise ProbeError(f"target soc_id is not SM8150/339: {soc!r}")
    else:
        soc = SOC_ID
    return {
        "model": EXPECTED_MODEL,
        "soc": EXPECTED_SOC,
        "soc_id": soc,
        "runtime_version": EXPECTED_RUNTIME,
        "runtime_build": EXPECTED_RUNTIME_BUILD,
        "kernel": EXPECTED_KERNEL,
        "bootloader": "A908NKSU5EWA3",
        "debug_level": "0x494d",
        "force_upload": force_upload,
        "dump_sink": dump_sink,
    }


def parse_selftest(payload: bytes, label: str = "selftest") -> dict[str, int]:
    text = _one_line(payload, label)
    match = re.fullmatch(
        r"selftest: pass=[0-9]+ warn=[0-9]+ fail=[0-9]+ "
        r"duration=[0-9]+ms entries=[0-9]+",
        text,
    )
    if match is None:
        raise ProbeError(f"{label} lacks exactly one selftest summary")
    values = {
        key: int(value)
        for key, value in re.findall(r"(pass|warn|fail|duration|entries)=([0-9]+)", text)
    }
    result = {
        "passed": values["pass"],
        "warn": values["warn"],
        "fail": values["fail"],
        "duration": values["duration"],
        "entries": values["entries"],
    }
    if result != {
        "passed": 11,
        "warn": 1,
        "fail": 0,
        "duration": result["duration"],
        "entries": 12,
    }:
        raise ProbeError(f"{label} is not exact 11/1/0/12: {result}")
    return result


def classify_value(mode: str, value: int) -> str:
    if value in {MAP_FAILURE_RESULT, -1}:
        # A returned -1 is a candidate result in either mode, never the
        # transport no-value refusal category.
        return "MAP_FAILED"
    if mode not in MODES:
        raise ProbeError(f"unsupported mode: {mode!r}")
    if mode == MODE_CONTROL:
        return "CONTROL_PASS" if value == CONTROL_SENTINEL else "CONTROL_FAILED"
    if 0 <= value <= 0xFFFFFFFF:
        return "READABLE_SECURITY_INDICATOR"
    return "INCIDENT"


def _partial_from_exception(exc: BaseException) -> dict[str, object]:
    """Copy bounded partial transport data into private evidence."""

    frame = getattr(exc, "partial_frame", None)
    if frame is None:
        frame = getattr(exc, "frame", None)
    payload = getattr(exc, "partial_payload", None)
    transcript = getattr(exc, "partial_transcript", None)
    begin = getattr(exc, "partial_begin", None)
    end = getattr(exc, "partial_end", None)
    partial = getattr(exc, "partial", None)
    if partial is not None:
        if isinstance(partial, Mapping):
            payload = partial.get("payload", payload)
            transcript = partial.get("transcript", transcript)
            begin = partial.get("begin", begin)
            end = partial.get("end", end)
        else:
            payload = getattr(partial, "payload", payload)
            transcript = getattr(partial, "transcript", transcript)
            begin = getattr(partial, "begin", begin)
            end = getattr(partial, "end", end)
    if frame is not None:
        payload = getattr(frame, "payload", payload)
        transcript = getattr(frame, "transcript", transcript)
        begin = getattr(frame, "begin", begin)
        end = getattr(frame, "end", end)
    payload_bounded = not isinstance(payload, bytes) or len(payload) <= MAX_PARTIAL_EVIDENCE_BYTES
    transcript_bounded = (
        not isinstance(transcript, bytes)
        or len(transcript) <= MAX_PARTIAL_EVIDENCE_BYTES
    )
    result: dict[str, object] = {
        "exception_type": type(exc).__name__,
        "exception_text": str(exc),
        "payload_base64": (
            base64.b64encode(payload).decode("ascii")
            if isinstance(payload, bytes) and payload_bounded
            else None
        ),
        "payload_sha256": sha256_bytes(payload) if isinstance(payload, bytes) else None,
        "payload_size": len(payload) if isinstance(payload, bytes) else None,
        "transcript_base64": (
            base64.b64encode(transcript).decode("ascii")
            if isinstance(transcript, bytes) and transcript_bounded
            else None
        ),
        "transcript_sha256": (
            sha256_bytes(transcript) if isinstance(transcript, bytes) else None
        ),
        "transcript_size": len(transcript) if isinstance(transcript, bytes) else None,
        "begin": dict(begin) if isinstance(begin, Mapping) else None,
        "end": dict(end) if isinstance(end, Mapping) else None,
        "payload_bounded": payload_bounded,
        "transcript_bounded": transcript_bounded,
    }
    if isinstance(exc, OperationReturnedError) and exc.frame_returned:
        # Keep the returned classification explicit in the private error
        # projection instead of making consumers infer it from the exception
        # name alone.
        result["transport_no_value"] = False
    return result


def _retained_partial_begin_matches_fixed_op(
    exc: BaseException, command: Sequence[str]
) -> bool:
    """Bind retained partial BEGIN metadata to the one fixed command.

    A fixed-op no-value observation must include exactly one retained BEGIN;
    absence of a BEGIN is pre-exchange ambiguity, not safe negative evidence.
    If either side is present, require one canonical protocol line, exact
    metadata equality, the fixed command name, fixed argv count, protocol
    flags, and no extra fields.  This keeps a stale/foreign partial frame
    from becoming a synthetic no-value observation.
    """

    missing = object()
    raw_begin: object = getattr(exc, "partial_begin", missing)
    raw_transcript: object = getattr(exc, "partial_transcript", missing)
    retained_partial = getattr(exc, "partial", None)
    if retained_partial is not None:
        if isinstance(retained_partial, Mapping):
            if "begin" in retained_partial:
                raw_begin = retained_partial.get("begin")
            if "transcript" in retained_partial:
                raw_transcript = retained_partial.get("transcript")
        else:
            partial_begin = getattr(retained_partial, "begin", missing)
            partial_transcript = getattr(retained_partial, "transcript", missing)
            if partial_begin is not missing:
                raw_begin = partial_begin
            if partial_transcript is not missing:
                raw_transcript = partial_transcript
    frame = getattr(exc, "partial_frame", None)
    if frame is None:
        frame = getattr(exc, "frame", None)
    if frame is not None:
        raw_begin = getattr(frame, "begin", raw_begin)
        raw_transcript = getattr(frame, "transcript", raw_transcript)

    # A retained partial object without transcript bytes cannot prove that the
    # fixed command reached the device; it is never no-value evidence.
    if raw_transcript is missing or raw_transcript is None:
        return False
    if not isinstance(raw_transcript, bytes):
        return False
    if raw_begin is not missing and raw_begin is not None and not isinstance(
        raw_begin, Mapping
    ):
        return False

    begin_matches = list(BEGIN_RE.finditer(raw_transcript))
    if raw_transcript.count(b"A90P1 BEGIN") != len(begin_matches):
        # Count malformed/non-line BEGIN tokens too; they are not proof of a
        # clean no-value boundary and must not be silently ignored.
        return False
    if raw_begin is missing or raw_begin is None:
        return False
    if len(begin_matches) != 1:
        return False
    try:
        transcript_begin = parse_fields(begin_matches[0].group("fields"))
    except (UnicodeDecodeError, ValueError):
        return False
    begin = dict(raw_begin)
    if transcript_begin != begin:
        return False
    expected_command = command[0] if command else None
    sequence = begin.get("seq")
    if (
        expected_command is None
        or begin.get("cmd") != expected_command
        or not isinstance(sequence, str)
        or re.fullmatch(r"[0-9]+", sequence) is None
        or (len(sequence) > 1 and sequence.startswith("0"))
    ):
        return False
    if set(begin) != {"seq", "cmd", "argc", "flags"}:
        return False
    if (
        begin.get("argc") != str(len(command))
        or begin.get("flags") != protocol_flags_for_argv(command)
    ):
        return False
    return True


def _retained_partial_payload_matches_transcript(exc: BaseException) -> bool:
    """Bind retained partial payload bytes exactly to transcript bytes.

    The native transport derives ``PartialEvidence.payload`` from the bytes
    after the last observed BEGIN in its bounded transcript.  Preserve that
    invariant here: an absent BEGIN proves no payload only when the retained
    payload is actually ``None``; a singular BEGIN requires the exact suffix,
    including an empty suffix.  A summary-only payload cannot create a
    no-value observation.
    """

    missing = object()
    raw_payload: object = getattr(exc, "partial_payload", missing)
    raw_transcript: object = getattr(exc, "partial_transcript", missing)
    retained_partial = getattr(exc, "partial", None)
    if retained_partial is not None:
        if isinstance(retained_partial, Mapping):
            if "payload" in retained_partial:
                raw_payload = retained_partial.get("payload")
            if "transcript" in retained_partial:
                raw_transcript = retained_partial.get("transcript")
        else:
            partial_payload = getattr(retained_partial, "payload", missing)
            partial_transcript = getattr(retained_partial, "transcript", missing)
            if partial_payload is not missing:
                raw_payload = partial_payload
            if partial_transcript is not missing:
                raw_transcript = partial_transcript
    frame = getattr(exc, "partial_frame", None)
    if frame is None:
        frame = getattr(exc, "frame", None)
    if frame is not None:
        raw_payload = getattr(frame, "payload", raw_payload)
        raw_transcript = getattr(frame, "transcript", raw_transcript)

    if not isinstance(raw_transcript, bytes):
        return False
    if len(raw_transcript) > MAX_PARTIAL_EVIDENCE_BYTES:
        return False
    begin_matches = list(BEGIN_RE.finditer(raw_transcript))
    if raw_transcript.count(b"A90P1 BEGIN") != len(begin_matches):
        return False
    if not begin_matches:
        return raw_payload is None
    if len(begin_matches) != 1 or not isinstance(raw_payload, bytes):
        return False
    try:
        parse_fields(begin_matches[0].group("fields"))
    except (UnicodeDecodeError, ValueError):
        return False
    return raw_payload == raw_transcript[begin_matches[0].end() :]


def _is_transport_no_value(
    exc: BaseException, command: Sequence[str] | None = None
) -> bool:
    """Accept only native typed partial transport failures as no-value.

    The no-value branch is a narrow transport observation, not a generic
    exception bucket.  Both the exact native ``TransportFailure`` class and
    its exact ``PartialEvidence`` payload are required; legacy timeout,
    connection, and OS exceptions remain INCIDENT even when they carry
    similarly named attributes.
    """

    typed_failure = getattr(native_transport, "TransportFailure", None)
    partial_type = getattr(native_transport, "PartialEvidence", None)
    if (
        not isinstance(typed_failure, type)
        or type(exc) is not typed_failure
        or not isinstance(partial_type, type)
        or type(getattr(exc, "partial", None)) is not partial_type
    ):
        return False

    expected_command = tuple(command) if command is not None else fixed_op_argv()
    if expected_command != fixed_op_argv():
        return False
    if not _retained_partial_begin_matches_fixed_op(exc, expected_command):
        return False
    if not _retained_partial_payload_matches_transcript(exc):
        return False

    partial = _partial_from_exception(exc)
    encoded_payload = partial.get("payload_base64")
    if not isinstance(encoded_payload, str):
        # A typed failure before the protocol BEGIN is not evidence that the
        # fixed operation reached the device.  Durable host dispatch intent
        # cannot turn that pre-exchange ambiguity into REFUSED_AT_MID.
        return False
    try:
        retained_payload = base64.b64decode(encoded_payload.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        return False
    if not is_transport_no_value_payload(retained_payload):
        return False
    encoded_transcript = partial.get("transcript_base64")
    if not isinstance(encoded_transcript, str):
        return False
    try:
        retained_transcript = base64.b64decode(
            encoded_transcript.encode("ascii"), validate=True
        )
    except (UnicodeEncodeError, ValueError):
        return False
    begin_matches = list(BEGIN_RE.finditer(retained_transcript))
    if (
        len(begin_matches) != 1
        or retained_transcript.count(b"A90P1 BEGIN") != len(begin_matches)
    ):
        return False
    # A complete END, retained terminal frame, or protocol value belongs to
    # the returned/error path, never the bounded no-value branch.  This is a
    # structural check over the retained bytes/fields, not an exception-text
    # heuristic.
    if partial.get("end") is not None:
        return False
    for key in ("payload_base64", "transcript_base64"):
        encoded = partial.get(key)
        if encoded is None:
            continue
        try:
            data = base64.b64decode(str(encoded).encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError):
            return False
        if len(data) > MAX_PARTIAL_EVIDENCE_BYTES or b"A90P1 END" in data:
            return False
    for key in ("payload_size", "transcript_size"):
        size = partial.get(key)
        if isinstance(size, int) and size > MAX_PARTIAL_EVIDENCE_BYTES:
            return False
    return True


def _transport_no_value_evidence(
    exc: BaseException, command: Sequence[str]
) -> dict[str, object]:
    """Decorate partial transport evidence with a fixed one-shot identity."""

    evidence = _partial_from_exception(exc)
    payload = getattr(exc, "partial_payload", None)
    transcript = getattr(exc, "partial_transcript", None)
    partial = getattr(exc, "partial", None)
    if isinstance(partial, Mapping):
        payload = partial.get("payload", payload)
        transcript = partial.get("transcript", transcript)
    elif partial is not None:
        payload = getattr(partial, "payload", payload)
        transcript = getattr(partial, "transcript", transcript)
    frame = getattr(exc, "partial_frame", None)
    if frame is None:
        frame = getattr(exc, "frame", None)
    if frame is not None:
        payload = getattr(frame, "payload", payload)
        transcript = getattr(frame, "transcript", transcript)
    evidence.update(
        {
            "evidence_id": "fixed_op_4",
            "argv": list(command),
            "transport_no_value": _is_transport_no_value(exc, command),
            "partial_evidence_present": (
                getattr(exc, "partial", None) is not None
                or any(
                    getattr(exc, name, None) is not None
                    for name in (
                        "partial_frame",
                        "partial_payload",
                        "partial_transcript",
                        "partial_begin",
                        "partial_end",
                    )
                )
            ),
            "a90r_present": (
                isinstance(payload, bytes)
                and b"A90R" in payload
            )
            or (isinstance(transcript, bytes) and b"A90R" in transcript),
            "bounded": bool(
                evidence.get("payload_bounded")
                and evidence.get("transcript_bounded")
            ),
        }
    )
    return evidence


def _record_frame(
    frames: list[dict[str, object]], evidence_id: str, argv: tuple[str, ...], frame: Any
) -> None:
    frames.append(frame_record(evidence_id, argv, frame))


def _bridge_bindings_match(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Compare identity-bearing bridge fields while ignoring validation time."""

    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def _parse_exact_lines(payload: bytes, label: str) -> dict[str, str]:
    """Parse an ASCII key=value response while rejecting duplicates."""

    if not isinstance(payload, bytes):
        raise ProbeError(f"{label} is not bytes")
    if b"\r" in payload.replace(b"\r\n", b""):
        raise ProbeError(f"{label} contains a bare CR")
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProbeError(f"{label} is not ASCII") from exc
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text or "\x00" in text:
        raise ProbeError(f"{label} is empty or contains NUL")
    lines = text.split("\n")
    if any(not line for line in lines):
        raise ProbeError(f"{label} contains an empty line")
    result: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            raise ProbeError(f"{label} has malformed line: {line!r}")
        key, value = line.split("=", 1)
        if not key or not value or key in result:
            raise ProbeError(f"{label} has duplicate key: {key!r}")
        result[key] = value
    if not result:
        raise ProbeError(f"{label} is empty")
    return result


def _parse_boot_sysfs_uevent(payload: bytes) -> dict[str, str]:
    """Parse the fixed sda24 uevent and return its current canonical dev_t."""

    fields = _parse_exact_lines(payload, "sda24 uevent")
    expected_static_fields = {
        "DEVNAME": "sda24",
        "DEVTYPE": "partition",
        "PARTN": BOOT_EXPECTED_PARTN,
        "PARTNAME": BOOT_EXPECTED_PARTNAME,
    }
    if set(fields) != {"MAJOR", "MINOR", *expected_static_fields}:
        raise ProbeError(f"sda24 uevent fields are not exact: {fields!r}")
    major = _parse_canonical_devnum(
        fields.get("MAJOR"),
        "sda24 uevent MAJOR",
        BOOT_MAJOR_MIN,
        BOOT_MAJOR_MAX,
    )
    minor = _parse_canonical_devnum(
        fields.get("MINOR"),
        "sda24 uevent MINOR",
        BOOT_MINOR_MIN,
        BOOT_MINOR_MAX,
    )
    for key, expected in expected_static_fields.items():
        if fields.get(key) != expected:
            raise ProbeError(
                f"sda24 uevent {key} is not exact: {fields.get(key)!r}"
            )
    return {
        "MAJOR": major,
        "MINOR": minor,
        **{key: fields[key] for key in expected_static_fields},
    }


def _attest_one(
    host: str,
    port: int,
    timeout: float,
    command: Command,
    frames: list[dict[str, object]],
    *,
    exchange_fn: Callable[..., Any] | None = None,
) -> Any:
    transport = exchange if exchange_fn is None else exchange_fn
    frame = transport(host, port, command, timeout)
    validate_complete_frame(frame, command.argv, command.evidence_id)
    _record_frame(frames, command.evidence_id, command.argv, frame)
    return frame


def _exchange_checked(
    host: str,
    port: int,
    timeout: float,
    command: Command,
    frames: list[dict[str, object]],
    *,
    allow_error: bool = False,
    allow_stophud_busy: bool = False,
) -> Any:
    """Exchange, validate, and retain one complete frame before continuing."""

    if allow_error:
        frame = exchange(
            host,
            port,
            command,
            timeout,
            allow_error=True,
        )
    else:
        frame = exchange(host, port, command, timeout)
    try:
        validate_complete_frame(
            frame,
            command.argv,
            command.evidence_id,
            allow_stophud_busy=allow_stophud_busy,
        )
    except BaseException:
        # Retain a malformed complete return for the incident journal, but
        # never let it authorize a subsequent exchange.
        _record_frame(frames, command.evidence_id, command.argv, frame)
        raise
    _record_frame(frames, command.evidence_id, command.argv, frame)
    return frame


def _attest_marker(
    host: str,
    port: int,
    timeout: float,
    evidence_id: str,
    path: str,
    frames: list[dict[str, object]],
    *,
    exchange_fn: Callable[..., Any] | None = None,
) -> None:
    frame = _attest_one(
        host,
        port,
        timeout,
        Command(evidence_id, ("run", "/bin/toybox", "test", "!", "-e", path)),
        frames,
        exchange_fn=exchange_fn,
    )
    # ``test ! -e`` has no stdout on success.  Keeping this assertion makes a
    # mocked transport unable to silently turn a present path into evidence
    # of absence while the actual A90 command still relies on rc/status.
    require_empty_toybox_payload(frame.payload, f"{path} absence check")
    symlink_frame = _attest_one(
        host,
        port,
        timeout,
        Command(
            evidence_id + "_not_symlink",
            ("run", "/bin/toybox", "test", "!", "-L", path),
        ),
        frames,
        exchange_fn=exchange_fn,
    )
    require_empty_toybox_payload(
        symlink_frame.payload, f"{path} symlink absence check"
    )


def stop_autohud(
    host: str,
    port: int,
    timeout: float,
    frames: list[dict[str, object]],
    journal: dict[str, object],
    journal_path: Path,
    bridge_binding: Mapping[str, object],
) -> dict[str, object]:
    """Adapt the shared arbitration to this tool's durable journal."""

    if not isinstance(bridge_binding, Mapping):
        raise ProbeError("stophud arbitration lacks the initial bridge binding")

    def guarded_exchange(
        exchange_host: str,
        exchange_port: int,
        command: Command,
        exchange_timeout: float,
        **kwargs: object,
    ) -> Any:
        # ``run_stophud`` invokes this wrapper immediately before every
        # attempt, including each busy retry.  Keep the revalidation and the
        # exact identity comparison adjacent to the one real exchange so a
        # holder handoff cannot turn a stale initial bind into a command.
        current = revalidate_bridge_binding(bridge_binding)
        if not isinstance(current, Mapping) or not _bridge_bindings_match(
            bridge_binding, current
        ):
            raise ProbeError("bridge binding drifted before stophud attempt")
        frame = exchange(
            exchange_host,
            exchange_port,
            command,
            exchange_timeout,
            **kwargs,
        )
        return frame

    def validate_stophud_frame(frame: Any) -> Any:
        return validate_complete_frame(
            frame,
            STOPHUD_ARGV,
            "stophud attempt",
            allow_stophud_busy=True,
        )

    def persist(attempts: list[dict[str, object]]) -> None:
        latest = attempts[-1]
        journal["stophud_attempts"] = list(attempts)
        journal["stophud_accepted"] = False
        journal["status"] = (
            "STOPHUD_BUSY_RETRY"
            if latest.get("rc") == -16 and latest.get("status") == "busy"
            else "STOPHUD_RESULT"
        )
        _atomic_json(journal_path, journal)

    result = run_stophud(
        host,
        port,
        timeout,
        guarded_exchange,
        frame_records=frames,
        persist=persist,
        validate_frame=validate_stophud_frame,
        max_attempts=STOPHUD_MAX_ATTEMPTS,
    )
    journal["stophud_accepted"] = True
    journal["status"] = "STOPHUD_ACCEPTED"
    _atomic_json(journal_path, journal)
    return result


def _cleanup_boot_attestation(
    host: str,
    port: int,
    timeout: float,
    frames: list[dict[str, object]],
    *,
    exchange_fn: Callable[..., Any] | None = None,
    bridge_binding: Mapping[str, object] | None = None,
    revalidate_fn: Callable[[Mapping[str, object]], Mapping[str, object]] | None = None,
    record: dict[str, object] | None = None,
) -> str | None:
    if revalidate_fn is None:
        revalidate_fn = revalidate_bridge_binding
    errors: list[str] = []
    for evidence_id, path in (
        ("boot_attest_remove_node", BOOT_ATTEST_NODE),
        ("boot_attest_remove_file", BOOT_ATTEST_FILE),
    ):
        try:
            if bridge_binding is not None:
                _attestation_bind(
                    bridge_binding,
                    revalidate_fn,
                    evidence_id + " binding",
                    record if record is not None else {},
                )
            frame = _attest_one(
                host,
                port,
                timeout,
                Command(evidence_id, ("run", "/bin/toybox", "rm", "-f", path)),
                frames,
                exchange_fn=exchange_fn,
            )
            require_empty_toybox_payload(frame.payload, evidence_id)
        except BaseException as exc:
            errors.append(f"{evidence_id}: {type(exc).__name__}: {exc}")
            # A cleanup failure (including a binding failure) means the
            # remaining mutation commands cannot be trusted.  Preserve the
            # incident and stop without issuing another mutation or absence
            # probe through an endpoint whose identity is now uncertain.
            return "; ".join(errors)
    for evidence_id, path in (
        ("boot_attest_node_absent", BOOT_ATTEST_NODE),
        ("boot_attest_file_absent", BOOT_ATTEST_FILE),
    ):
        try:
            _attest_marker(
                host,
                port,
                timeout,
                evidence_id,
                path,
                frames,
                exchange_fn=exchange_fn,
            )
        except BaseException as exc:
            errors.append(f"{evidence_id}: {type(exc).__name__}: {exc}")
            return "; ".join(errors)
    return "; ".join(errors) if errors else None


def _attestation_bind(
    initial: Mapping[str, object],
    revalidate_fn: Callable[[Mapping[str, object]], Mapping[str, object]],
    stage: str,
    record: dict[str, object],
) -> Mapping[str, object]:
    """Freshly bind the exact bridge immediately before one mutation group."""

    current = revalidate_fn(initial)
    if not isinstance(current, Mapping) or not _bridge_bindings_match(initial, current):
        raise ProbeError(f"bridge binding drifted before {stage}")
    events = record.setdefault("binding_events", [])
    if isinstance(events, list):
        events.append({"stage": stage, "bridge_binding": dict(current)})
    return current


def attest_current_boot(
    host: str,
    port: int,
    timeout: float,
    expected_hash: str,
    frames: list[dict[str, object]],
    *,
    bridge_binding: Mapping[str, object] | None = None,
    exchange_fn: Callable[..., Any] | None = None,
    revalidate_fn: Callable[[Mapping[str, object]], Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Attest the currently running boot prefix immediately before dispatch.

    The sysfs identity is checked first, then a fixed experiment-owned block
    node is made and exactly ``bs=4096,count=14864`` bytes are captured.  The
    temporary node and capture file are removed on every path and their
    absence is proved before the caller may rebind the bridge or dispatch op
    4.  A stale or valid historical flash receipt cannot satisfy this gate.
    """

    record: dict[str, object] = {
        "sysfs_root": BOOT_SYSFS_ROOT,
        "block_node": BOOT_BLOCK_NODE,
        "attest_node": BOOT_ATTEST_NODE,
        "attest_file": BOOT_ATTEST_FILE,
        "bs": 4096,
        "count": 14864,
        "expected_size": BOOT_PREFIX_SIZE,
        "expected_sha256": expected_hash,
        "cleanup_ok": False,
        "binding_events": [],
    }
    if bridge_binding is None:
        bridge_binding = validate_bridge_binding()
    if revalidate_fn is None:
        revalidate_fn = revalidate_bridge_binding
    primary_error: BaseException | None = None
    binding_failure = False
    try:
        # Clear any abandoned experiment-owned objects and prove a clean
        # starting point before creating the block node.
        try:
            _attestation_bind(
                bridge_binding, revalidate_fn, "pre-attestation cleanup", record
            )
        except BaseException:
            binding_failure = True
            raise
        pre_cleanup_error = _cleanup_boot_attestation(
            host,
            port,
            timeout,
            frames,
            exchange_fn=exchange_fn,
            bridge_binding=bridge_binding,
            revalidate_fn=revalidate_fn,
            record=record,
        )
        record["pre_cleanup_error"] = pre_cleanup_error
        if pre_cleanup_error is not None:
            binding_failure = True
            raise ProbeError(
                f"abandoned boot attestation objects could not be cleaned: {pre_cleanup_error}"
            )
        _attest_marker(
            host,
            port,
            timeout,
            "boot_attest_pre_node_absent",
            BOOT_ATTEST_NODE,
            frames,
            exchange_fn=exchange_fn,
        )
        _attest_marker(
            host,
            port,
            timeout,
            "boot_attest_pre_file_absent",
            BOOT_ATTEST_FILE,
            frames,
            exchange_fn=exchange_fn,
        )

        uevent = _attest_one(
            host,
            port,
            timeout,
            Command("boot_sysfs_uevent", ("cat", BOOT_SYSFS_UEVENT)),
            frames,
            exchange_fn=exchange_fn,
        )
        fields = _parse_boot_sysfs_uevent(uevent.payload)
        major = fields["MAJOR"]
        minor = fields["MINOR"]
        record["sysfs_uevent"] = dict(fields)

        size_frame = _attest_one(
            host,
            port,
            timeout,
            Command("boot_sysfs_size", ("cat", BOOT_SYSFS_SIZE)),
            frames,
            exchange_fn=exchange_fn,
        )
        size_text = _one_line(size_frame.payload, "sda24 size")
        if size_text != BOOT_EXPECTED_SECTORS:
            raise ProbeError(f"sda24 sectors are not exact: {size_text!r}")
        ro_frame = _attest_one(
            host,
            port,
            timeout,
            Command("boot_sysfs_ro", ("cat", BOOT_SYSFS_RO)),
            frames,
            exchange_fn=exchange_fn,
        )
        ro_text = _one_line(ro_frame.payload, "sda24 ro")
        if ro_text != "0":
            raise ProbeError(f"sda24 ro is not exact zero: {ro_text!r}")
        record["sectors"] = int(size_text, 10)
        record["ro"] = int(ro_text, 10)

        try:
            _attestation_bind(bridge_binding, revalidate_fn, "attestation mkdir", record)
        except BaseException:
            binding_failure = True
            raise
        mkdir_frame = _attest_one(
            host,
            port,
            timeout,
            Command(
                "boot_attest_mkdir",
                ("run", "/bin/toybox", "mkdir", "-p", BOOT_ATTEST_DIR),
            ),
            frames,
            exchange_fn=exchange_fn,
        )
        require_empty_toybox_payload(mkdir_frame.payload, "boot_attest_mkdir")
        try:
            _attestation_bind(bridge_binding, revalidate_fn, "attestation mknod", record)
        except BaseException:
            binding_failure = True
            raise
        mknod_frame = _attest_one(
            host,
            port,
            timeout,
            Command(
                "boot_attest_mknod",
                ("mknodb", BOOT_ATTEST_NODE, major, minor),
            ),
            frames,
            exchange_fn=exchange_fn,
        )
        if getattr(mknod_frame, "payload", None) != b"":
            raise ProbeError("boot_attest_mknod returned an unexpected payload")
        stat_frame = _attest_one(
            host,
            port,
            timeout,
            Command(
                "boot_attest_stat_node",
                ("stat", BOOT_ATTEST_NODE),
            ),
            frames,
            exchange_fn=exchange_fn,
        )
        stat_fields = _parse_stat_identity(stat_frame.payload, major, minor)
        record["stat"] = stat_fields
        try:
            _attestation_bind(bridge_binding, revalidate_fn, "attestation capture", record)
        except BaseException:
            binding_failure = True
            raise
        capture_frame = _attest_one(
            host,
            port,
            timeout,
            Command(
                "boot_attest_capture",
                (
                    "run",
                    "/bin/toybox",
                    "dd",
                    f"if={BOOT_ATTEST_NODE}",
                    f"of={BOOT_ATTEST_FILE}",
                    "bs=4096",
                    "count=14864",
                    "conv=fsync",
                    "status=none",
                ),
            ),
            frames,
            exchange_fn=exchange_fn,
        )
        require_empty_toybox_payload(capture_frame.payload, "boot_attest_capture")
        hash_frame = _attest_one(
            host,
            port,
            timeout,
            Command(
                "boot_attest_hash",
                ("run", "/bin/toybox", "sha256sum", BOOT_ATTEST_FILE),
            ),
            frames,
            exchange_fn=exchange_fn,
        )
        hash_body = parse_toybox_payload(
            hash_frame.payload, "sda24 prefix SHA-256"
        )
        match = re.fullmatch(
            rb"([0-9a-f]{64})  " + re.escape(BOOT_ATTEST_FILE.encode("ascii")),
            hash_body,
        )
        if match is None:
            raise ProbeError(f"sda24 prefix SHA-256 is malformed: {hash_body!r}")
        hash_text = match.group(1).decode("ascii")
        size_capture = _attest_one(
            host,
            port,
            timeout,
            Command(
                "boot_attest_size",
                ("run", "/bin/toybox", "wc", "-c", BOOT_ATTEST_FILE),
            ),
            frames,
            exchange_fn=exchange_fn,
        )
        capture_size = parse_toybox_wc_count(size_capture.payload, BOOT_ATTEST_FILE)
        record.update(
            {
                "captured_sha256": hash_text,
                "captured_size": capture_size,
                "hash_matches_candidate": hash_text == expected_hash,
                "size_matches_candidate": capture_size == BOOT_PREFIX_SIZE,
            }
        )
        if hash_text != expected_hash or capture_size != BOOT_PREFIX_SIZE:
            raise ProbeError(
                "current boot prefix differs from selected candidate: "
                f"sha256={hash_text!r} size={capture_size!r}"
            )
    except BaseException as exc:
        primary_error = exc

    cleanup_error: str | None = None
    if not binding_failure:
        try:
            _attestation_bind(
                bridge_binding, revalidate_fn, "post-attestation cleanup", record
            )
        except BaseException as exc:
            binding_failure = True
            cleanup_error = f"{type(exc).__name__}: {exc}"
        else:
            cleanup_error = _cleanup_boot_attestation(
                host,
                port,
                timeout,
                frames,
                exchange_fn=exchange_fn,
                bridge_binding=bridge_binding,
                revalidate_fn=revalidate_fn,
                record=record,
            )
    else:
        cleanup_error = "bridge binding failure prevented post-attestation cleanup"
    record["cleanup_error"] = cleanup_error
    record["cleanup_ok"] = cleanup_error is None
    record["binding_failure"] = binding_failure
    if primary_error is not None:
        try:
            setattr(primary_error, "attestation_record", record)
        except BaseException:
            pass
        if cleanup_error is not None:
            combined = ProbeError(
                f"current boot attestation failed: {primary_error}; cleanup: {cleanup_error}"
            )
            setattr(combined, "attestation_record", record)
            raise combined from primary_error
        raise primary_error
    if cleanup_error is not None:
        combined = ProbeError(f"current boot attestation cleanup failed: {cleanup_error}")
        setattr(combined, "attestation_record", record)
        raise combined
    return record


def _safe_path(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def _refuse_existing(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise ProbeError(f"journal/output already exists; replay forbidden: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ProbeError(f"journal/output temporary already exists: {path}.tmp")


def _path_under(path: Path, parent: Path, label: str) -> Path:
    """Resolve a path and require it to remain under one evidence root."""

    if path.is_symlink():
        raise ProbeError(f"{label} must not be a symlink: {path}")
    if parent.is_symlink():
        raise ProbeError(f"{label} parent must not be a symlink: {parent}")
    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical.parent
    parent_lexical = parent if parent.is_absolute() else Path.cwd() / parent
    while True:
        if cursor.is_symlink():
            raise ProbeError(f"{label} parent component must not be a symlink: {cursor}")
        if cursor == parent_lexical or cursor == Path(cursor.anchor or "/"):
            break
        cursor = cursor.parent
    resolved = path.resolve(strict=False)
    parent_resolved = parent.resolve(strict=False)
    try:
        resolved.relative_to(parent_resolved)
    except ValueError as exc:
        raise ProbeError(f"{label} must be under {parent_resolved}") from exc
    return resolved


def _strict_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"flash journal contains duplicate key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ProbeError(f"flash journal contains non-finite number: {value}")


def _read_json_no_follow(path: Path) -> tuple[dict[str, object], bytes]:
    """Read one regular private journal without following its leaf symlink."""

    if path.is_symlink():
        raise ProbeError(f"flash journal must not be a symlink: {path}")
    try:
        fd = _open_regular_nofollow(path)
    except OSError as exc:
        raise ProbeError(f"cannot open flash journal: {path}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ProbeError("flash journal is not a regular file")
        if info.st_size < 0 or info.st_size > MAX_FLASH_JOURNAL_BYTES:
            raise ProbeError(
                f"flash journal exceeds bounded size {MAX_FLASH_JOURNAL_BYTES}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_FLASH_JOURNAL_BYTES - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FLASH_JOURNAL_BYTES:
                raise ProbeError(
                    f"flash journal exceeds bounded size {MAX_FLASH_JOURNAL_BYTES}"
                )
        after = os.fstat(fd)
        before_identity = (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or total != after.st_size:
            raise ProbeError("flash journal changed while being read")
    finally:
        os.close(fd)
    data = b"".join(chunks)
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError("flash journal is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ProbeError("flash journal root is not an object")
    return value, data


def verify_flash_journal(
    path: Path, mode: str, *, root: Path | None = None
) -> dict[str, object]:
    """Bind this probe to one successful, exact flash journal.

    A candidate's local hash does not prove that it was what booted.  The
    preceding flash journal must therefore be private, regular, complete,
    cleanly read back, and part of this profile's predecessor graph.
    """

    if mode not in FLASH_MODES:
        raise ProbeError(f"unsupported mode: {mode!r}")
    evidence_root = (REPO_ROOT if root is None else Path(root)).resolve()
    private_root = evidence_root / "evidence" / "private"
    input_path = Path(path)
    if not input_path.is_absolute():
        input_path = evidence_root / input_path
    checked_path = _path_under(input_path, private_root, "flash journal")
    expected_path = _fixed_flash_journal_path(evidence_root, mode).resolve()
    if checked_path != expected_path:
        raise ProbeError("flash journal path is not the fixed V024 producer journal")
    journal, data = _read_json_no_follow(checked_path)
    expected_hash = FLASH_EXPECTED_HASHES[mode]
    expected_predecessors = sorted(ALLOWED_PREDECESSORS[mode])
    remote_staging = FLASH_REMOTE_STAGING[mode]
    expected_effect_argv = [
        "dd",
        f"if={remote_staging}",
        "of=/dev/block/sda24",
        "bs=4096",
        "count=14864",
        "conv=fsync",
    ]
    required: dict[str, object] = {
        "schema": "sdm855-a90-remapper-boot-flash-private-v1",
        "profile": mode,
        "image_sha256": expected_hash,
        "image_size": BOOT_PREFIX_SIZE,
        "remote_staging": remote_staging,
        "remote_staging_sha256": expected_hash,
        "remote_staging_size": BOOT_PREFIX_SIZE,
        "readback_sha256": expected_hash,
        "readback_size": BOOT_PREFIX_SIZE,
        "predecessor_size": BOOT_PREFIX_SIZE,
        # The boot producer records the pre-effect staging/predecessor proof
        # before arming its durable write marker.  Requiring those exact
        # fields keeps an old summary-only flash receipt from authorizing a
        # later inline operation.
        "post_staging_predecessor_size": BOOT_PREFIX_SIZE,
        "post_staging_predecessor_revalidated": True,
        "allowed_predecessors": expected_predecessors,
        "write_count": 1,
        "effect_dispatched": True,
        "effect_armed": True,
        "effect_argv": expected_effect_argv,
        "status": PASS_READBACK_AND_CLEANUP,
        "staging_removed": True,
        "pre_staging_removed": True,
        "pre_cleanup_error": None,
        "cleanup_error": None,
        "error": None,
        "reboot_dispatched": False,
        "partition_writes": True,
        "staging_attempted": True,
        "staging_attempt_count": 1,
        "staging_dispatch_count": 1,
        "staging_status": "STAGING_PUSH_RETURNED",
        "target_model": RECOVERY_TARGET_MODEL,
        "target_device": RECOVERY_TARGET_DEVICE,
        "target_serial_sha256": RECOVERY_TARGET_SERIAL_SHA256,
        "boot_alias": "/dev/block/by-name/boot",
        "boot_node": "/dev/block/sda24",
        "post_staging_revalidated": True,
        "pre_effect_revalidated": True,
        "post_dispatch_revalidated": True,
        "final_revalidated": True,
        "pre_cleanup_revalidated": True,
        "pre_push_revalidated": True,
        "final_cleanup_revalidated": True,
        "post_dispatch_staging_sha256": expected_hash,
        "post_dispatch_staging_size": BOOT_PREFIX_SIZE,
        "pre_cleanup_target_serial_sha256": RECOVERY_TARGET_SERIAL_SHA256,
        "pre_push_target_serial_sha256": RECOVERY_TARGET_SERIAL_SHA256,
        "post_staging_target_serial_sha256": RECOVERY_TARGET_SERIAL_SHA256,
        "pre_effect_target_serial_sha256": RECOVERY_TARGET_SERIAL_SHA256,
        "post_dispatch_target_serial_sha256": RECOVERY_TARGET_SERIAL_SHA256,
        "final_target_serial_sha256": RECOVERY_TARGET_SERIAL_SHA256,
        "final_cleanup_target_serial_sha256": RECOVERY_TARGET_SERIAL_SHA256,
    }
    for key, expected in required.items():
        actual = journal.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ProbeError(
                f"flash journal field {key!r} is not exact: "
                f"{actual!r} != {expected!r}"
            )
    for alias in (
        "post_staging_rebind_serial_sha256",
        "pre_effect_rebind_serial_sha256",
        "post_dispatch_rebind_serial_sha256",
        "final_rebind_serial_sha256",
    ):
        if alias in journal and journal[alias] != RECOVERY_TARGET_SERIAL_SHA256:
            raise ProbeError(f"flash journal field {alias!r} is not exact")
    completed = journal.get("completed_utc")
    if not isinstance(completed, str):
        raise ProbeError("flash journal completed_utc is missing or not text")
    try:
        parsed_completed = dt.datetime.strptime(completed, "%Y-%m-%dT%H:%M:%S+00:00")
    except ValueError as exc:
        raise ProbeError("flash journal completed_utc is not exact UTC") from exc
    if parsed_completed.tzinfo is not None:
        raise ProbeError("flash journal completed_utc must have fixed UTC form")
    predecessor = journal.get("predecessor_sha256")
    if type(predecessor) is not str or predecessor not in ALLOWED_PREDECESSORS[mode]:
        raise ProbeError(f"flash journal predecessor is not allowed for {mode}")
    if journal.get("post_staging_predecessor_sha256") != predecessor:
        raise ProbeError("flash journal post-staging predecessor differs")
    if journal.get("post_dispatch_predecessor_sha256") != predecessor:
        raise ProbeError("flash journal post-dispatch predecessor differs")
    guarded = journal.get("guarded_effect_receipt")
    if not isinstance(guarded, Mapping):
        raise ProbeError("flash journal guarded effect receipt is missing")
    if set(guarded) != {"schema", "guard", "dd_result", "write_count"}:
        raise ProbeError("flash journal guarded effect receipt fields are not exact")
    if guarded.get("schema") != "sdm855-a90-remapper-guarded-effect-v1":
        raise ProbeError("flash journal guarded effect receipt schema is not exact")
    if type(guarded.get("write_count")) is not int or guarded.get("write_count") != 1:
        raise ProbeError("flash journal guarded effect receipt write count is not exact")
    guard = guarded.get("guard")
    dd_result = guarded.get("dd_result")
    if not isinstance(guard, Mapping) or not isinstance(dd_result, Mapping):
        raise ProbeError("flash journal guarded effect receipt sections are missing")
    if set(guard) != {"current_sha256", "current_size", "staging_sha256", "staging_size"}:
        raise ProbeError("flash journal guarded effect guard fields are not exact")
    if guard != {
        "current_sha256": predecessor,
        "current_size": str(BOOT_PREFIX_SIZE),
        "staging_sha256": expected_hash,
        "staging_size": str(BOOT_PREFIX_SIZE),
    }:
        raise ProbeError("flash journal guarded effect guard values differ")
    if dd_result != {"rc": "0", "count": "14864"}:
        raise ProbeError("flash journal guarded effect result is not exact")
    return {
        "path": str(checked_path),
        "sha256": sha256_bytes(data),
        "size": len(data),
        "profile": mode,
        "image_sha256": expected_hash,
        "readback_sha256": expected_hash,
        "predecessor_sha256": predecessor,
        "record": journal,
    }


def _parse_completed_utc(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ProbeError(f"{label} completed_utc is missing or not text")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S+00:00")
    except ValueError as exc:
        raise ProbeError(f"{label} completed_utc is not exact UTC") from exc
    return parsed.replace(tzinfo=dt.timezone.utc)


def verify_control_manifest(path: Path, *, root: Path | None = None) -> dict[str, object]:
    """Authorize the fixed control receipt through the independent finalizer.

    The finalizer owns the complete producer contract, including every frame
    payload and transcript.  This read-side helper only performs the small
    hash/path/chronology projection needed by the inline collector after that
    authority has accepted the fixed receipt.
    """

    evidence_root = (REPO_ROOT if root is None else Path(root)).resolve()
    manifest_root = evidence_root / "evidence" / "manifests"
    private_root = evidence_root / "evidence" / "private"
    checked = _path_under(Path(path), manifest_root, "control manifest")
    if checked != _fixed_control_manifest_path(evidence_root).resolve():
        raise ProbeError(
            "control manifest path is not the fixed Verification 024 control path"
        )

    # Keep the import lazy: the finalizer imports this probe's fixed parser
    # and flash helpers at module load, so importing it above would create a
    # circular initialization path.  Nothing is authorized until this exact
    # finalizer call accepts the fixed manifest/root pair.
    try:
        from tools import a90_verification024_finalize as finalizer
    except ModuleNotFoundError:  # Direct execution from tools/.
        import a90_verification024_finalize as finalizer  # type: ignore
    try:
        finalizer_receipt = finalizer.validate_control(checked, evidence_root)
    except BaseException as exc:
        raise ProbeError(
            "control manifest failed independent finalizer validation"
        ) from exc
    if not isinstance(finalizer_receipt, Mapping):
        raise ProbeError("control finalizer returned a malformed receipt")
    for key, expected in {
        "predecessor_capsule_sha256": CONTROL_R2_PREDECESSOR_CAPSULE_SHA256,
        "predecessor_capsule_size": CONTROL_R2_PREDECESSOR_CAPSULE_SIZE,
    }.items():
        actual = finalizer_receipt.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ProbeError(
                f"control finalizer predecessor descriptor {key!r} is not exact"
            )

    manifest, manifest_bytes = _read_json_no_follow(checked)
    raw_path = _path_under(
        private_root / f"{CONTROL_EXPERIMENT_ID}.json",
        private_root,
        "control raw evidence",
    )
    journal_path = _path_under(
        private_root / f"{CONTROL_EXPERIMENT_ID}.journal.json",
        private_root,
        "control journal",
    )
    raw, raw_bytes = _read_json_no_follow(raw_path)
    journal, journal_bytes = _read_json_no_follow(journal_path)

    manifest_sha256 = sha256_bytes(manifest_bytes)
    raw_sha256 = sha256_bytes(raw_bytes)
    journal_sha256 = sha256_bytes(journal_bytes)
    hash_bindings = {
        "raw_snapshot_sha256": raw_sha256,
        "raw_snapshot_size": len(raw_bytes),
        "journal_sha256": journal_sha256,
        "journal_size": len(journal_bytes),
    }
    for key, expected in hash_bindings.items():
        actual = manifest.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ProbeError(f"control manifest hash/size binding {key!r} differs")

    completed = _parse_completed_utc(
        manifest.get("completed_utc"), "control manifest"
    )
    for label, record in (("control raw", raw), ("control journal", journal)):
        record_completed = _parse_completed_utc(
            record.get("completed_utc"), label
        )
        if record_completed != completed:
            raise ProbeError(f"{label} completion time differs from control manifest")

    manifest_attestation = manifest.get("current_boot_attestation")
    fixed_measurement = raw.get("fixed_op_measurement")
    if not isinstance(manifest_attestation, Mapping):
        raise ProbeError("control manifest attestation projection is missing")
    if not isinstance(fixed_measurement, Mapping):
        raise ProbeError("control raw fixed-op measurement projection is missing")

    summary = {
        "experiment_id": CONTROL_EXPERIMENT_ID,
        "manifest_path": str(checked),
        "manifest_sha256": manifest_sha256,
        "manifest_size": len(manifest_bytes),
        "raw_path": str(raw_path),
        "raw_sha256": raw_sha256,
        "raw_size": len(raw_bytes),
        "journal_path": str(journal_path),
        "journal_sha256": journal_sha256,
        "journal_size": len(journal_bytes),
        "completed_utc": manifest["completed_utc"],
        "mode": MODE_CONTROL,
        "candidate_sha256": CONTROL_SHA256,
        "candidate_size": BOOT_PREFIX_SIZE,
        "value": "0x000000000000c071",
        "target_model": EXPECTED_MODEL,
        "target_device": "r3q",
        "target_dmid": "SM-A908N/SM8150",
        "current_boot_attestation": dict(manifest_attestation),
        "boot_id_before_read_sha256": manifest.get("boot_id_before_read_sha256"),
        "fixed_op_measurement": dict(fixed_measurement),
        "semantic_claim_sha256": raw.get("semantic_claim_sha256"),
        "semantic_claim_size": raw.get("semantic_claim_size"),
        "semantic_claim_key_sha256": raw.get("semantic_claim_key_sha256"),
        "predecessor_capsule_sha256": finalizer_receipt.get(
            "predecessor_capsule_sha256"
        ),
        "predecessor_capsule_size": finalizer_receipt.get(
            "predecessor_capsule_size"
        ),
    }

    # Bind every field consumed by READ to the receipt returned by the
    # independent finalizer.  Missing, substituted, or type-confused values
    # cannot become authorization just because local summary parsing passed.
    finalizer_projection = {
        "kind": "control",
        "experiment_id": summary["experiment_id"],
        "path": summary["manifest_path"],
        "sha256": summary["manifest_sha256"],
        "size": summary["manifest_size"],
        "manifest_sha256": summary["manifest_sha256"],
        "manifest_size": summary["manifest_size"],
        "raw_sha256": summary["raw_sha256"],
        "raw_size": summary["raw_size"],
        "journal_sha256": summary["journal_sha256"],
        "journal_size": summary["journal_size"],
        "completed_utc": summary["completed_utc"],
        "value": summary["value"],
        "candidate_sha256": summary["candidate_sha256"],
        "candidate_size": summary["candidate_size"],
        "target_dmid": summary["target_dmid"],
        "current_boot_attestation": summary["current_boot_attestation"],
        "boot_id_before_read_sha256": summary["boot_id_before_read_sha256"],
        "fixed_op_measurement": summary["fixed_op_measurement"],
        "semantic_claim_sha256": summary["semantic_claim_sha256"],
        "semantic_claim_size": summary["semantic_claim_size"],
        "semantic_claim_key_sha256": summary["semantic_claim_key_sha256"],
        "predecessor_capsule_sha256": summary["predecessor_capsule_sha256"],
        "predecessor_capsule_size": summary["predecessor_capsule_size"],
        "raw_path": summary["raw_path"],
        "journal_path": summary["journal_path"],
    }
    for key, expected in finalizer_projection.items():
        actual = finalizer_receipt.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ProbeError(
                f"control manifest finalizer receipt binding {key!r} differs"
            )
    return summary


def _publish(
    root: Path,
    experiment_id: str,
    raw: dict[str, object],
    manifest: dict[str, object],
) -> tuple[Path, Path]:
    raw_path = root / "evidence/private" / f"{experiment_id}.json"
    public_path = root / "evidence/manifests" / f"{experiment_id}.manifest.json"
    _refuse_existing(raw_path)
    _refuse_existing(public_path)
    raw_bytes = json_bytes(raw)
    manifest = dict(manifest)
    manifest["raw_snapshot_sha256"] = sha256_bytes(raw_bytes)
    manifest["raw_snapshot_size"] = len(raw_bytes)
    write_new(raw_path, raw_bytes, 0o600)
    write_new(public_path, json_bytes(manifest), 0o644)
    return raw_path, public_path


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if not getattr(args, "execute", False):
        raise ProbeError("MID probe requires explicit --execute")
    timeout = getattr(args, "timeout", None)
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(float(timeout))
        or not 0 < float(timeout) <= MAX_TIMEOUT_SEC
    ):
        raise ProbeError(f"timeout must be within 0 < timeout <= {MAX_TIMEOUT_SEC:g}")
    if args.mode not in MODES:
        raise ProbeError(f"unsupported mode: {args.mode!r}")
    if args.mode == MODE_CONTROL and hasattr(args, "control_manifest"):
        raise ProbeError("control mode rejects injected --control-manifest")
    if args.mode == MODE_READ and args.experiment_id != READ_SOURCE_EXPERIMENT_ID:
        raise ProbeError("read mode requires the fixed Verification 024 read experiment ID")
    if args.mode == MODE_CONTROL and args.experiment_id != CONTROL_EXPERIMENT_ID:
        raise ProbeError("control mode requires the fixed Verification 024 control experiment ID")
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ProbeError("experiment ID has invalid characters")
    if args.host != BRIDGE_HOST or args.port != BRIDGE_PORT:
        raise ProbeError("probe accepts only the pinned loopback A90 bridge")

    root = _fixed_output_root(args)
    private_path = root / "evidence/private" / f"{args.experiment_id}.json"
    public_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    journal_path = root / "evidence/private" / f"{args.experiment_id}.journal.json"
    _fixed_selector_path(
        args,
        "journal",
        journal_path,
        root=root,
    )
    private_path = _path_under(
        private_path, root / "evidence" / "private", "private evidence"
    )
    public_path = _path_under(
        public_path, root / "evidence" / "manifests", "public manifest"
    )
    for path in (journal_path, private_path, public_path):
        _refuse_existing(path)

    fixed_flash_path = _fixed_flash_journal_path(root, args.mode)
    _fixed_selector_path(
        args,
        "flash_journal",
        fixed_flash_path,
        root=root,
    )
    if args.mode == MODE_READ:
        _fixed_selector_path(
            args,
            "control_manifest",
            _fixed_control_manifest_path(root),
            root=root,
            allow_absent=True,
        )

    predecessor_capsule: dict[str, object] | None = None
    predecessor_capsule_bytes: bytes | None = None
    predecessor_capsule_descriptor: dict[str, object] | None = None
    preclaim_bytes: bytes | None = None
    if args.mode == MODE_CONTROL:
        # This is the first durable action in the control-r2 route.  It uses
        # only fixed constants and O_EXCL; no candidate, transport, flash or
        # predecessor evidence is read before this owner exists.
        preclaim = _control_r2_preclaim()
        preclaim_bytes = _exclusive_json(journal_path, preclaim)
        predecessor_capsule, predecessor_capsule_bytes, predecessor_capsule_descriptor = (
            _load_control_r2_predecessor()
        )

    candidate_path = DEFAULT_CANDIDATES[args.mode]
    expected_hash = EXPECTED_CANDIDATE_HASHES[args.mode]
    candidate_size, actual_hash = _stable_file_digest(candidate_path)
    if candidate_size != BOOT_PREFIX_SIZE:
        raise ProbeError("fixed candidate does not have exact boot-prefix size")
    if actual_hash != expected_hash:
        raise ProbeError(
            f"{args.mode} candidate SHA-256 mismatch: {actual_hash} != {expected_hash}"
        )
    transport_evidence = _validate_local_transport()

    flash_journal = verify_flash_journal(
        fixed_flash_path, args.mode, root=root
    )
    control_receipt: dict[str, object] | None = None
    if args.mode == MODE_READ:
        control_receipt = verify_control_manifest(
            _fixed_control_manifest_path(root), root=root
        )
        control_completed = _parse_completed_utc(
            control_receipt["completed_utc"], "control receipt"
        )
        flash_completed = _parse_completed_utc(
            flash_journal["record"].get("completed_utc"), "read flash journal"
        )
        if flash_completed <= control_completed:
            raise ProbeError(
                "read flash receipt must complete strictly after control receipt"
            )

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    journal: dict[str, object] = {
        "schema": "sdm855-a90-inline-remapper-mid-journal-v1",
        "status": "INTENT_DURABLE_PRE_DISPATCH",
        "experiment_id": args.experiment_id,
        "mode": args.mode,
        "candidate_sha256": expected_hash,
        "candidate_size": BOOT_PREFIX_SIZE,
        "transport_module": LOCAL_TRANSPORT_MODULE,
        "transport_source": LOCAL_TRANSPORT_SOURCE,
        "transport_source_sha256": LOCAL_TRANSPORT_SOURCE_SHA256,
        "transport_source_size": transport_evidence["source_size"],
        "transport_source_verified": True,
        "fixed_op": {
            "op": OP_FIXED_READ,
            "args": [],
            "buffer_size": FIXED_OP_BUFFER_SIZE,
            "buffer_sha256": sha256_bytes(build_fixed_op_buffer()),
        },
        "flash_journal_bound": True,
        "flash_journal_sha256": flash_journal["sha256"],
        "flash_journal_size": flash_journal["size"],
        "flash_profile": flash_journal["profile"],
        "flash_image_sha256": flash_journal["image_sha256"],
        "flash_readback_sha256": flash_journal["readback_sha256"],
        "flash_predecessor_sha256": flash_journal["predecessor_sha256"],
        "flash_completed_utc": flash_journal["record"].get("completed_utc"),
        "op": OP_FIXED_READ,
        "op_args": [],
        "replay_safe": False,
        "dispatch_count": 0,
        "effect_dispatched": False,
        "effect_replayed": False,
        "automatic_retries": False,
        "memory_or_mmio_writes": False,
        "reboot_dispatched": False,
        "flash_journal": {
            "path": flash_journal["path"],
            "sha256": flash_journal["sha256"],
            "size": flash_journal["size"],
            "profile": flash_journal["profile"],
            "image_sha256": flash_journal["image_sha256"],
            "readback_sha256": flash_journal["readback_sha256"],
            "predecessor_sha256": flash_journal["predecessor_sha256"],
        },
        "semantic_claim_path": None,
        "semantic_claim_sha256": None,
        "semantic_claim_size": None,
        "semantic_claim_key_sha256": None,
        "semantic_claimed": False,
        "control_manifest": control_receipt,
        "started_utc": started,
    }
    if args.mode == MODE_CONTROL:
        if (
            preclaim_bytes is None
            or predecessor_capsule is None
            or predecessor_capsule_bytes is None
            or predecessor_capsule_descriptor is None
        ):
            raise ProbeError("control-r2 predecessor preclaim is incomplete")
        journal["control_r2_predecessor"] = {
            "preclaim_sha256": sha256_bytes(preclaim_bytes),
            "preclaim_size": len(preclaim_bytes),
            "capsule": predecessor_capsule,
            "capsule_sha256": predecessor_capsule_descriptor["sha256"],
            "capsule_size": predecessor_capsule_descriptor["size"],
        }
        # The preclaim already owns this final inode.  Upgrade it only after
        # candidate/transport/flash validation, preserving the original
        # preclaim hash/size and the full redacted capsule in one section.
        _atomic_json(journal_path, journal)
    else:
        _exclusive_json(journal_path, journal)

    frames: list[dict[str, object]] = []
    target: dict[str, object] | None = None
    bridge_binding: Mapping[str, object] | None = None
    pre_dispatch_binding: Mapping[str, object] | None = None
    panic_before: int | None = None
    panic_transition_started = False
    panic_zero_set = False
    panic_zero_verified = False
    panic_restore_verified = False
    panic_restore_attempted = False
    panic_restore_deferred = False
    panic_zero_binding: Mapping[str, object] | None = None
    restore_binding: Mapping[str, object] | None = None
    attestation: dict[str, object] | None = None
    attestation_binding: Mapping[str, object] | None = None
    boot_id_before_read: str | None = None
    stophud_result: dict[str, object] | None = None
    fixed_measurement: dict[str, object] | None = None
    semantic_claim_path: Path | None = None
    semantic_claim_sha256: str | None = None
    semantic_claim_size: int | None = None
    semantic_claim_key_sha256: str | None = None
    semantic_claimed = False
    value: int | None = None
    outcome = "INCIDENT"
    failed_stage: str | None = "preflight"
    error: dict[str, object] | None = None
    health_after: dict[str, object] = {}
    dispatch_count = 0
    dispatch_returned = False
    dispatch_failed = False
    target_verified = False
    effect_ambiguous = False
    final_bridge_bound = False

    try:
        # Host-side bridge validation precedes any A90P1 command.  Its result
        # is retained privately; the public manifest exposes only a boolean.
        bridge_binding = validate_bridge_binding()
        if not isinstance(bridge_binding, Mapping):
            raise ProbeError("initial bridge binding is not an object")
        # Autohud may race the first A90P1 command after boot.  Stop it only
        # through this fixed command and retry only the explicit not-executed
        # rc=-16/status=busy result; all other errors fail closed.
        stophud_result = stop_autohud(
            args.host,
            args.port,
            args.timeout,
            frames,
            journal,
            journal_path,
            bridge_binding,
        )
        version_command = Command("version_before", ("version",))
        version_frame = _exchange_checked(
            args.host, args.port, args.timeout, version_command, frames
        )
        cmdline_command = Command("cmdline_before", ("cat", "/proc/cmdline"))
        cmdline_frame = _exchange_checked(
            args.host, args.port, args.timeout, cmdline_command, frames
        )
        soc_command = Command("soc_id_before", ("cat", "/sys/devices/soc0/soc_id"))
        soc_frame = _exchange_checked(
            args.host, args.port, args.timeout, soc_command, frames
        )
        target = validate_target(
            version_frame.payload, cmdline_frame.payload, soc_frame.payload
        )
        selftest_command = Command("selftest_before", ("selftest", "status"))
        selftest_before = _exchange_checked(
            args.host, args.port, args.timeout, selftest_command, frames
        )
        target["selftest_before"] = parse_selftest(
            selftest_before.payload, "selftest_before"
        )
        panic_command = Command(
            "panic_before", ("cat", "/proc/sys/kernel/panic_on_oops")
        )
        panic_frame = _exchange_checked(
            args.host, args.port, args.timeout, panic_command, frames
        )
        panic_before = _parse_exact_sysctl(panic_frame.payload, "1")

        # This current-boot attestation is deliberately after target gates and
        # before the sysctl transition.  It closes the historical-receipt-only
        # gap: the image actually running now must hash to the selected mode.
        attestation = attest_current_boot(
            args.host,
            args.port,
            args.timeout,
            expected_hash,
            frames,
            bridge_binding=bridge_binding,
        )
        # The attestation cleanup is itself a bridge-visible lifecycle.  Bind
        # the exact bridge again immediately after its strict node/file
        # absence proof before collecting the causal pre-read boot ID.
        attestation_binding = revalidate_bridge_binding(bridge_binding)
        if not isinstance(attestation_binding, Mapping):
            raise ProbeError("post-attestation bridge binding is not an object")
        if not _bridge_bindings_match(bridge_binding, attestation_binding):
            raise ProbeError("bridge binding drifted after boot attestation cleanup")
        boot_id_command = Command("boot_id_before_read", ("cat", BOOT_ID_PATH))
        boot_id_frame = _exchange_checked(
            args.host, args.port, args.timeout, boot_id_command, frames
        )
        boot_id_before_read = parse_boot_id(
            boot_id_frame.payload, "pre-read boot_id"
        )
        # Serialize same-boot/mode/candidate owners before any panic sysctl
        # mutation or durable effect marker.  Different experiment IDs cannot
        # bypass this fixed semantic O_EXCL claim.
        semantic_claim_path, semantic_claim_data, semantic_claim_key_sha256 = _semantic_claim(
            root,
            args.mode,
            expected_hash,
            BOOT_PREFIX_SIZE,
            boot_id_before_read,
            args.experiment_id,
        )
        semantic_claim_sha256 = sha256_bytes(semantic_claim_data)
        semantic_claim_size = len(semantic_claim_data)
        semantic_claimed = True
        journal.update(
            {
                "status": "PANIC_TRANSITION_INTENT_DURABLE",
                "target": target,
                "current_boot_attestation": attestation,
                "boot_id_before_read": boot_id_before_read,
                "boot_id_before_read_sha256": sha256_bytes(
                    boot_id_before_read.encode("ascii")
                ),
                "semantic_claim_path": str(semantic_claim_path),
                "semantic_claim_sha256": semantic_claim_sha256,
                "semantic_claim_size": semantic_claim_size,
                "semantic_claim_key_sha256": semantic_claim_key_sha256,
                "semantic_claimed": semantic_claimed,
                "panic_on_oops_before": panic_before,
                "temporary_sysctl_write_intent": True,
                "temporary_sysctl_write": False,
                "device_state_write": False,
            }
        )
        # This durable revision is the arm record for the temporary device
        # state change.  It must exist before set_panic_on_oops(0).
        _atomic_json(journal_path, journal)
        # The durable intent/claim is now on disk.  Freshly revalidate the
        # exact bridge and issue the state-changing write immediately; no
        # host fsync or other device command may occur between the bind and
        # this write.
        panic_zero_binding = revalidate_bridge_binding(attestation_binding)
        if not isinstance(panic_zero_binding, Mapping):
            raise ProbeError("panic-zero bridge binding is not an object")
        if not _bridge_bindings_match(bridge_binding, panic_zero_binding):
            raise ProbeError("bridge binding drifted before panic_on_oops zero")
        panic_transition_started = True
        _write_panic_on_oops(args.host, args.port, args.timeout, 0, frames)
        panic_zero_set = True
        panic_zero_command = Command(
            "panic_zero_verify", ("cat", "/proc/sys/kernel/panic_on_oops")
        )
        panic_zero_frame = _exchange_checked(
            args.host, args.port, args.timeout, panic_zero_command, frames
        )
        _parse_exact_sysctl(panic_zero_frame.payload, "0")
        panic_zero_verified = True

        # Record the completed zero transition only after its write/readback
        # returned.  This receipt is intentionally not part of the pre-write
        # durable intent path.
        journal.update(
            {
                "status": "PANIC_TRANSITION_COMPLETE",
                "post_attestation_revalidation": {
                    "status": "PASS",
                    "bridge_binding": dict(attestation_binding),
                },
                "panic_zero_revalidation": {
                    "status": "PASS",
                    "bridge_binding": dict(panic_zero_binding),
                },
                "panic_on_oops_zero_set": panic_zero_set,
                "panic_on_oops_zero_verified": panic_zero_verified,
            }
        )
        _atomic_json(journal_path, journal)
        target_verified = True
        journal.update(
            {
                "status": "PREPARED",
                "target": target,
                "bridge_binding": dict(bridge_binding),
                "panic_on_oops_zero_set": panic_zero_set,
                "panic_on_oops_zero_verified": panic_zero_verified,
            }
        )
        _atomic_json(journal_path, journal)
        journal.update(
            {
                "status": "EFFECT_DISPATCH_STARTED",
                "effect_dispatched": True,
                "dispatch_count": 1,
            }
        )
        _atomic_json(journal_path, journal)
        failed_stage = "fixed-op-4"
        dispatch_count = 1
        # Exactly one fixed ExtendedCommand: no caller-controlled
        # address/value reaches the hash-pinned command buffer.
        # The effect marker is durable.  Revalidate immediately before the
        # sole op-4 exchange, with no host fsync/device command in between.
        pre_dispatch_binding = revalidate_bridge_binding(attestation_binding)
        if not isinstance(pre_dispatch_binding, Mapping):
            raise ProbeError("pre-dispatch bridge binding is not an object")
        if not _bridge_bindings_match(bridge_binding, pre_dispatch_binding):
            raise ProbeError("bridge binding drifted before fixed op dispatch")
        try:
            value, fixed_measurement = run_fixed_inline_op(
                args.host, args.port, args.timeout, frames
            )
            dispatch_returned = True
            outcome = classify_value(args.mode, value)
        except OperationReturnedError as op_returned_exc:
            # A complete END frame is a returned operation even when the
            # device reports a malformed result or an error status.  Restore
            # panic_on_oops before any other post-op command in that case.
            dispatch_returned = True
            outcome = "INCIDENT"
            fixed_measurement = {
                "returned_frame_error": str(op_returned_exc),
            }
            error = _partial_from_exception(op_returned_exc)

        # The fixed op has now returned (including a complete malformed
        # result).  Bind its pre-dispatch identity after that outcome, before
        # arming the separate panic-restore intent.
        journal["pre_dispatch_revalidation"] = {
            "status": "PASS",
            "bridge_binding": dict(pre_dispatch_binding),
        }
        journal["fixed_op_returned"] = dispatch_returned
        _atomic_json(journal_path, journal)

        # A returned operation always gets the mandatory 1 restore and
        # immediate readback before any bridge/health command.  A transport
        # exception from the operation never enters this block.
        try:
            if pre_dispatch_binding is None:
                raise ProbeError("panic restore lacks pre-dispatch bridge binding")
            journal.update(
                {
                    "status": "PANIC_RESTORE_INTENT_DURABLE",
                    "panic_restore_intent": True,
                }
            )
            _atomic_json(journal_path, journal)
            restore_binding = revalidate_bridge_binding(pre_dispatch_binding)
            if not isinstance(restore_binding, Mapping) or not _bridge_bindings_match(
                pre_dispatch_binding, restore_binding
            ):
                raise ProbeError("bridge binding drifted before panic restore")
            panic_restore_attempted = True
            _write_panic_on_oops(args.host, args.port, args.timeout, 1, frames)
            restore_command = Command(
                "panic_restore_verify", ("cat", "/proc/sys/kernel/panic_on_oops")
            )
            restore_frame = _exchange_checked(
                args.host, args.port, args.timeout, restore_command, frames
            )
            _parse_exact_sysctl(restore_frame.payload, "1")
            panic_restore_verified = True
            # Record the fresh binding only after the restore write and its
            # exact readback have returned; it must not split bind from the
            # state-changing write.
            journal["pre_restore_revalidation"] = {
                "status": "PASS",
                "bridge_binding": dict(restore_binding),
            }
            journal["panic_restore_effect_returned"] = True
            _atomic_json(journal_path, journal)
        except BaseException as restore_exc:
            if restore_binding is not None:
                # The restore bind happened before the restore effect raised;
                # persist that receipt only after the raise, never between
                # the bind and the write.
                journal["pre_restore_revalidation"] = {
                    "status": "PASS",
                    "bridge_binding": dict(restore_binding),
                }
            panic_restore_deferred = True
            restore_error = _partial_from_exception(restore_exc)
            error = restore_error
            failed_stage = "panic-on-oops-restore"
            if outcome == "CONTROL_PASS":
                outcome = "CONTROL_FAILED"
        if panic_restore_verified:
            journal.update(
                {
                    "status": "EFFECT_RETURNED",
                    "value": f"0x{value:016x}" if value is not None else None,
                    "fixed_op_measurement": fixed_measurement,
                    "outcome": outcome,
                    "effect_ambiguous": False,
                }
            )
            _atomic_json(journal_path, journal)
            failed_stage = None if outcome in {
                "CONTROL_PASS",
                "READABLE_SECURITY_INDICATOR",
            } else "result"
    except BaseException as exc:
        # Once op 4 has been dispatched, an exception is ambiguous.  In that
        # branch this handler performs host-only journaling and deliberately
        # sends no restore, bridge, or final-health command.
        if pre_dispatch_binding is not None:
            # The op has returned/raised before this binding receipt is
            # persisted; keeping it out of the pre-op path preserves the
            # bind -> immediate fixed-op adjacency.
            journal["pre_dispatch_revalidation"] = {
                "status": "PASS",
                "bridge_binding": dict(pre_dispatch_binding),
            }
            journal["fixed_op_returned"] = dispatch_returned
            _atomic_json(journal_path, journal)
        if panic_zero_binding is not None and "panic_zero_revalidation" not in journal:
            journal["panic_zero_revalidation"] = {
                "status": "PASS",
                "bridge_binding": dict(panic_zero_binding),
            }
        attestation_from_error = getattr(exc, "attestation_record", None)
        if isinstance(attestation_from_error, Mapping):
            attestation = dict(attestation_from_error)
        error = _partial_from_exception(exc)
        if dispatch_count and not dispatch_returned:
            dispatch_failed = True
            error = _transport_no_value_evidence(exc, fixed_op_argv())
            outcome = (
                "REFUSED_AT_MID_CANDIDATE"
                if args.mode == MODE_READ
                and _is_transport_no_value(exc, fixed_op_argv())
                else "CONTROL_FAILED"
                if args.mode == MODE_CONTROL
                else "INCIDENT"
            )
            failed_stage = "fixed-op-4"
            panic_restore_deferred = panic_transition_started
        elif dispatch_returned:
            # A post-return host/journal failure does not replay the operation.
            if outcome == "CONTROL_PASS":
                outcome = "CONTROL_FAILED"
            failed_stage = failed_stage or "result"
        else:
            outcome = "INCIDENT"
            failed_stage = failed_stage or "preflight"
            if panic_transition_started and not panic_restore_verified:
                # A failed zero transition/readback leaves the temporary
                # sysctl state unknown; do not issue a command through an
                # untrusted bridge.  Recovery owner must restore it.
                panic_restore_deferred = True
        effect_ambiguous = bool(dispatch_count and not dispatch_returned)
        journal.update(
            {
                "status": (
                    "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
                    if dispatch_count
                    else "REFUSED_PRE_DISPATCH"
                ),
                "outcome": outcome,
                "failed_stage": failed_stage,
                "error": error,
                "dispatch_count": dispatch_count,
                "effect_dispatched": bool(dispatch_count),
                "effect_ambiguous": effect_ambiguous,
            }
        )
        _atomic_json(journal_path, journal)
    finally:
        # A dispatch exception is a hard stop: no command may follow it.  A
        # READABLE returned value similarly stops after the mandatory sysctl
        # restore/verify; it is never followed by final-health traffic.
        if dispatch_failed:
            health_after = {
                "ok": False,
                "skipped": True,
                "reason": "dispatch_exception_restore_deferred",
            }
        elif not target_verified:
            health_after = {"ok": False, "skipped": True, "reason": "target_not_bound"}
        elif not dispatch_returned:
            health_after = {
                "ok": False,
                "skipped": True,
                "reason": "pre_dispatch_failure",
            }
        elif outcome == "READABLE_SECURITY_INDICATOR":
            health_after = {
                "ok": False,
                "skipped": True,
                "reason": "security_indicator_stop_after_restore",
            }
        elif outcome != "CONTROL_PASS":
            health_after = {
                "ok": False,
                "skipped": True,
                "reason": "non_control_result_stop_after_restore",
            }
        elif not panic_restore_verified:
            health_after = {
                "ok": False,
                "skipped": True,
                "reason": "panic_restore_unverified",
            }
        else:
            try:
                if pre_dispatch_binding is None:
                    raise ProbeError("post-dispatch health lacks pre-dispatch bridge binding")
                post_dispatch_binding = revalidate_bridge_binding(pre_dispatch_binding)
                if not isinstance(post_dispatch_binding, Mapping) or not _bridge_bindings_match(
                    pre_dispatch_binding, post_dispatch_binding
                ):
                    raise ProbeError("bridge binding drifted before final health")
                final_bridge_bound = True
                version_after_command = Command("version_after", ("version",))
                version_after = _exchange_checked(
                    args.host, args.port, args.timeout, version_after_command, frames
                )
                cmdline_after_command = Command(
                    "cmdline_after", ("cat", "/proc/cmdline")
                )
                cmdline_after = _exchange_checked(
                    args.host, args.port, args.timeout, cmdline_after_command, frames
                )
                selftest_after_command = Command(
                    "selftest_after", ("selftest", "status")
                )
                selftest_after = _exchange_checked(
                    args.host, args.port, args.timeout, selftest_after_command, frames
                )
                soc_after_command = Command(
                    "soc_id_after", ("cat", "/sys/devices/soc0/soc_id")
                )
                soc_after = _exchange_checked(
                    args.host, args.port, args.timeout, soc_after_command, frames
                )
                final_target = validate_target(
                    version_after.payload, cmdline_after.payload, soc_after.payload
                )
                final_selftest = parse_selftest(
                    selftest_after.payload, "selftest_after"
                )
                health_after = {
                    "ok": True,
                    "target": final_target,
                    "selftest": final_selftest,
                }
            except BaseException as health_exc:
                health_after = {
                    "ok": False,
                    "error": _partial_from_exception(health_exc),
                }
                if error is None:
                    error = _partial_from_exception(health_exc)
                if outcome == "CONTROL_PASS":
                    outcome = "CONTROL_FAILED"
                    failed_stage = "post-health"

    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    panic_transition = {
        "before": panic_before,
        "zero_write_attempted": panic_transition_started,
        "zero_set": panic_zero_set,
        "zero_verified": panic_zero_verified,
        "restore_write_attempted": panic_restore_attempted,
        "restored": panic_restore_verified,
        "restore_deferred": panic_restore_deferred,
        "proof_frame_ids": [
            evidence_id
            for evidence_id in (
                "panic_before",
                "panic_set_0",
                "panic_zero_verify",
                "panic_set_1",
                "panic_restore_verify",
            )
            if any(frame.get("evidence_id") == evidence_id for frame in frames)
        ],
    }
    if outcome == "READABLE_SECURITY_INDICATOR":
        promotion = "STOP_AND_ROLLBACK_REQUIRED"
    elif outcome == "REFUSED_AT_MID_CANDIDATE":
        promotion = "REQUIRES_LAST_KMSG_ROLLBACK_HEALTH"
    elif outcome == "CONTROL_PASS":
        promotion = "CONTROL_ONLY_NO_READ_AUTHORITY"
    else:
        promotion = "INCIDENT_RECONCILE_REQUIRED"
    cleanup_ok = panic_restore_verified
    if outcome == "CONTROL_PASS" and health_after.get("ok") is True and cleanup_ok:
        final_status = "CONTROL_VERIFIED"
    elif outcome == "READABLE_SECURITY_INDICATOR":
        final_status = "READABLE_SECURITY_INDICATOR"
    elif outcome in {"REFUSED_AT_MID_CANDIDATE", "CONTROL_FAILED"}:
        # Keep an ambiguous post-dispatch status distinct from the categorical
        # outcome so later reconciliation cannot be mistaken for a clean
        # negative or a completed control pass.
        current_status = str(journal.get("status", outcome))
        final_status = (
            current_status
            if current_status == "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
            else outcome
        )
    elif outcome == "MAP_FAILED":
        final_status = "MAP_FAILED"
    else:
        final_status = str(journal.get("status", "INCIDENT"))
    journal.update(
        {
            "completed_utc": completed,
            "outcome": outcome,
            "failed_stage": failed_stage,
            "error": error,
            "frames": frames,
            "health_after": health_after,
            "current_boot_attestation": attestation,
            "boot_id_before_read": boot_id_before_read,
            "boot_id_before_read_sha256": (
                sha256_bytes(boot_id_before_read.encode("ascii"))
                if boot_id_before_read is not None
                else None
            ),
            "semantic_claim_path": str(semantic_claim_path) if semantic_claim_path is not None else None,
            "semantic_claim_sha256": semantic_claim_sha256,
            "semantic_claim_size": semantic_claim_size,
            "semantic_claim_key_sha256": semantic_claim_key_sha256,
            "semantic_claimed": semantic_claimed,
            "fixed_op_measurement": fixed_measurement,
            "value": f"0x{value:016x}" if value is not None else None,
            "panic_on_oops_before": panic_before,
            "panic_on_oops_zero_set": panic_zero_set,
            "panic_on_oops_zero_verified": panic_zero_verified,
            "panic_on_oops_restored": panic_restore_verified,
            "panic_transition": panic_transition,
            "panic_restore_deferred": panic_restore_deferred,
            "temporary_sysctl_write_attempted": panic_transition_started,
            "temporary_sysctl_write": panic_zero_set,
            "device_state_write": (
                "UNKNOWN"
                if panic_transition_started and not panic_zero_set
                else panic_zero_set
            ),
            "cleanup_ok": cleanup_ok,
            "target_verified": target_verified,
            "dispatch_returned": dispatch_returned,
            "dispatch_failed": dispatch_failed,
            "promotion": promotion,
            "status": final_status,
            "stophud": stophud_result,
        }
    )
    _atomic_json(journal_path, journal)
    journal_size, journal_sha256 = _stable_file_digest(journal_path)

    raw = {
        "schema": "sdm855-a90-inline-remapper-mid-private-v1",
        "experiment_id": args.experiment_id,
        "mode": args.mode,
        "started_utc": started,
        "completed_utc": completed,
        "target": target,
        "candidate_sha256": expected_hash,
        "candidate_size": BOOT_PREFIX_SIZE,
        # Keep the inline raw/journal binding as one identical compact
        # receipt projection.  The complete producer journal is reopened and
        # validated by ``verify_flash_journal``; embedding it only in raw
        # would make a truthful producer output fail its own cross-bind gate.
        "flash_journal": {
            key: flash_journal[key]
            for key in (
                "path",
                "sha256",
                "size",
                "profile",
                "image_sha256",
                "readback_sha256",
                "predecessor_sha256",
            )
        },
        "control_manifest": control_receipt,
        "transport_module": LOCAL_TRANSPORT_MODULE,
        "transport_source": LOCAL_TRANSPORT_SOURCE,
        "transport_source_sha256": LOCAL_TRANSPORT_SOURCE_SHA256,
        "transport_source_size": transport_evidence["source_size"],
        "transport_source_verified": True,
        "op": OP_FIXED_READ,
        "op_args": [],
        "value": f"0x{value:016x}" if value is not None else None,
        "fixed_op_measurement": fixed_measurement,
        "outcome": outcome,
        "promotion": promotion,
        "security_classification": (
            "POTENTIAL_SECURITY_BOUNDARY_BYPASS"
            if outcome == "READABLE_SECURITY_INDICATOR"
            else "NOT_TRIGGERED"
        ),
        "failed_stage": failed_stage,
        "error": error,
        "frames": frames,
        "health_after": health_after,
        "current_boot_attestation": attestation,
        "boot_id_before_read": boot_id_before_read,
        "boot_id_before_read_sha256": (
            sha256_bytes(boot_id_before_read.encode("ascii"))
            if boot_id_before_read is not None
            else None
        ),
        "semantic_claim_path": str(semantic_claim_path) if semantic_claim_path is not None else None,
        "semantic_claim_sha256": semantic_claim_sha256,
        "semantic_claim_size": semantic_claim_size,
        "semantic_claim_key_sha256": semantic_claim_key_sha256,
        "semantic_claimed": semantic_claimed,
        "stophud": stophud_result,
        "bridge_binding": dict(bridge_binding) if bridge_binding is not None else None,
        "final_bridge_bound": final_bridge_bound,
        "panic_on_oops_before": panic_before,
        "panic_on_oops_zero_set": panic_zero_set,
        "panic_on_oops_zero_verified": panic_zero_verified,
        "panic_on_oops_restored": panic_restore_verified,
        "panic_transition": panic_transition,
        "panic_restore_deferred": panic_restore_deferred,
        "temporary_sysctl_write_attempted": panic_transition_started,
        "temporary_sysctl_write": panic_zero_set,
        "device_state_write": (
            "UNKNOWN"
            if panic_transition_started and not panic_zero_set
            else panic_zero_set
        ),
        "cleanup_ok": cleanup_ok,
        "dispatch_count": dispatch_count,
        # Keep the durable one-way marker and both dispatch terminal fields
        # in the private projection.  Consumers cross-bind all three copies
        # (journal/raw/public); an outcome string or count alone is not proof
        # that the fixed operation returned.
        "effect_dispatched": bool(dispatch_count),
        "dispatch_returned": dispatch_returned,
        "dispatch_failed": dispatch_failed,
        "effect_ambiguous": effect_ambiguous,
        "effect_replayed": False,
        "automatic_retries": False,
        "memory_or_mmio_writes": False,
        "controller_writes": False,
        "smc": False,
        "protected_memory_read": False,
        "partition_writes": False,
        "reboot_dispatched": False,
    }
    public = {
        "schema": "sdm855-a90-inline-remapper-mid-public-v1",
        "experiment_id": args.experiment_id,
        "mode": args.mode,
        "started_utc": started,
        "completed_utc": completed,
        "target_verified": target_verified,
        "target_evaluation": "VERIFIED" if target_verified else "NOT_EVALUATED",
        "target_model": EXPECTED_MODEL if target_verified else None,
        "soc": EXPECTED_SOC if target_verified else None,
        "runtime": EXPECTED_RUNTIME if target_verified else None,
        "candidate_sha256": expected_hash,
        "candidate_size": BOOT_PREFIX_SIZE,
        "transport_module": LOCAL_TRANSPORT_MODULE,
        "transport_source": LOCAL_TRANSPORT_SOURCE,
        "transport_source_sha256": LOCAL_TRANSPORT_SOURCE_SHA256,
        "transport_source_size": transport_evidence["source_size"],
        "transport_source_verified": True,
        "fixed_op": {
            "op": OP_FIXED_READ,
            "args": [],
            "buffer_size": FIXED_OP_BUFFER_SIZE,
            "buffer_sha256": sha256_bytes(build_fixed_op_buffer()),
            "rc": (
                fixed_measurement.get("rc")
                if isinstance(fixed_measurement, Mapping)
                else None
            ),
            "status": (
                fixed_measurement.get("status")
                if isinstance(fixed_measurement, Mapping)
                else None
            ),
            "value": (
                fixed_measurement.get("value")
                if isinstance(fixed_measurement, Mapping)
                else None
            ),
        },
        "flash_journal_bound": True,
        "flash_journal_sha256": flash_journal["sha256"],
        "flash_journal_size": flash_journal["size"],
        "flash_profile": flash_journal["profile"],
        "flash_image_sha256": flash_journal["image_sha256"],
        "flash_readback_sha256": flash_journal["readback_sha256"],
        "flash_predecessor_sha256": flash_journal["predecessor_sha256"],
        "flash_completed_utc": flash_journal["record"].get("completed_utc"),
        "control_manifest": (
            {
                "experiment_id": control_receipt["experiment_id"],
                "manifest_sha256": control_receipt["manifest_sha256"],
                "manifest_size": control_receipt["manifest_size"],
                "raw_sha256": control_receipt["raw_sha256"],
                "raw_size": control_receipt["raw_size"],
                "journal_sha256": control_receipt["journal_sha256"],
                "journal_size": control_receipt["journal_size"],
                "completed_utc": control_receipt["completed_utc"],
                "mode": control_receipt["mode"],
                "candidate_sha256": control_receipt["candidate_sha256"],
                "candidate_size": control_receipt["candidate_size"],
                "value": control_receipt["value"],
                "target_dmid": control_receipt["target_dmid"],
                "current_boot_attestation": {
                    key: control_receipt["current_boot_attestation"].get(key)
                    for key in (
                        "sysfs_root",
                        "block_node",
                        "bs",
                        "count",
                        "expected_size",
                        "captured_size",
                        "expected_sha256",
                        "captured_sha256",
                        "stat",
                        "sectors",
                        "ro",
                        "hash_matches_candidate",
                        "size_matches_candidate",
                        "cleanup_ok",
                        "sysfs_uevent",
                    )
                },
                "boot_id_before_read_sha256": control_receipt["boot_id_before_read_sha256"],
                "fixed_op_measurement": control_receipt["fixed_op_measurement"],
                "semantic_claim_sha256": control_receipt["semantic_claim_sha256"],
                "semantic_claim_size": control_receipt["semantic_claim_size"],
                "semantic_claim_key_sha256": control_receipt["semantic_claim_key_sha256"],
                "predecessor_capsule_sha256": control_receipt[
                    "predecessor_capsule_sha256"
                ],
                "predecessor_capsule_size": control_receipt[
                    "predecessor_capsule_size"
                ],
            }
            if control_receipt is not None
            else None
        ),
        "stophud_accepted": bool(stophud_result and stophud_result.get("accepted")),
        "stophud_busy_retries": (
            stophud_result.get("busy_retries", 0) if stophud_result is not None else 0
        ),
        "op": OP_FIXED_READ,
        "op_args": [],
        "outcome": outcome,
        "promotion": promotion,
        "security_classification": (
            "POTENTIAL_SECURITY_BOUNDARY_BYPASS"
            if outcome == "READABLE_SECURITY_INDICATOR"
            else "NOT_TRIGGERED"
        ),
        "clean_negative": False,
        "requires_last_kmsg_rollback_health": outcome == "REFUSED_AT_MID_CANDIDATE",
        "failed_stage": failed_stage,
        "dispatch_count": dispatch_count,
        "dispatch_returned": dispatch_returned,
        "dispatch_failed": dispatch_failed,
        # Keep the durable journal's one-way marker visible in the redacted
        # receipt as well.  Finalization must never infer dispatch merely
        # from a count or from an outcome string.
        "effect_dispatched": bool(dispatch_count),
        "effect_ambiguous": effect_ambiguous,
        "effect_replayed": False,
        "automatic_retries": False,
        "arbitrary_address_input": False,
        "generic_call_target": False,
        "memory_or_mmio_writes": False,
        "controller_writes": False,
        "smc": False,
        "protected_memory_read": False,
        "partition_writes": False,
        "reboot_dispatched": False,
        "bridge_bound": bridge_binding is not None,
        "final_bridge_bound": final_bridge_bound,
        "cleanup_ok": cleanup_ok,
        "health_after_ok": health_after.get("ok") is True,
        "panic_on_oops_before": panic_before if target_verified else None,
        "panic_on_oops_zero_set": panic_zero_set,
        "panic_on_oops_zero_verified": panic_zero_verified,
        "panic_on_oops_restored": panic_restore_verified,
        "panic_transition": panic_transition,
        "panic_restore_deferred": panic_restore_deferred,
        "transport_no_value": bool(
            isinstance(error, Mapping) and error.get("transport_no_value") is True
        ),
        "temporary_sysctl_write_attempted": panic_transition_started,
        "temporary_sysctl_write": panic_zero_set,
        "device_state_write": (
            "UNKNOWN"
            if panic_transition_started and not panic_zero_set
            else panic_zero_set
        ),
        "current_boot_attestation": (
            {
                "sysfs_root": attestation.get("sysfs_root"),
                "block_node": attestation.get("block_node"),
                "bs": attestation.get("bs"),
                "count": attestation.get("count"),
                "expected_size": attestation.get("expected_size"),
                "captured_size": attestation.get("captured_size"),
                "expected_sha256": attestation.get("expected_sha256"),
                "captured_sha256": attestation.get("captured_sha256"),
                "stat": attestation.get("stat"),
                "sectors": attestation.get("sectors"),
                "ro": attestation.get("ro"),
                "hash_matches_candidate": attestation.get("hash_matches_candidate"),
                "size_matches_candidate": attestation.get("size_matches_candidate"),
                "cleanup_ok": attestation.get("cleanup_ok"),
                "sysfs_uevent": attestation.get("sysfs_uevent"),
            }
            if attestation is not None
            else None
        ),
        "boot_id_before_read_sha256": (
            sha256_bytes(boot_id_before_read.encode("ascii"))
            if boot_id_before_read is not None
            else None
        ),
        "semantic_claim": (
            {
                "filename": semantic_claim_path.name,
                "sha256": semantic_claim_sha256,
                "size": semantic_claim_size,
                "key_sha256": semantic_claim_key_sha256,
            }
            if semantic_claim_path is not None
            else None
        ),
        "returned_value_present": value is not None,
        "returned_value_sha256": (
            sha256_bytes(f"0x{value:016x}".encode("ascii"))
            if value is not None
            else None
        ),
        "raw_value_omitted": True,
        "serial_identity_omitted": True,
        "raw_cmdline_omitted": True,
        "partial_transport_retained_private": error is not None,
        "private_record": {
            "filename": f"{args.experiment_id}.json",
            "journal_filename": f"{args.experiment_id}.journal.json",
            "git_ignored": True,
        },
        "journal_sha256": journal_sha256,
        "journal_size": journal_size,
        "claim_boundary": (
            "CONTROL_PASS proves only fixed map/unmap control returned 0xc071; "
            "it authorizes no read or write."
            if outcome == "CONTROL_PASS"
            else "READABLE_SECURITY_INDICATOR is a stop condition and potential "
            "security-boundary bypass; broad probing is forbidden."
            if outcome == "READABLE_SECURITY_INDICATOR"
            else "REFUSED_AT_MID_CANDIDATE is not a clean negative; promotion "
            "requires exact last-kmsg, rollback and final-health evidence."
            if outcome == "REFUSED_AT_MID_CANDIDATE"
            else "MAP_FAILED is a returned map-failure marker, not a transport "
            "negative; no reachability claim is authorized."
            if outcome == "MAP_FAILED"
            else "The incident does not establish MMIO reachability or refusal."
        ),
    }
    raw_path, public_path = _publish(root, args.experiment_id, raw, public)
    if outcome not in {"CONTROL_PASS", "READABLE_SECURITY_INDICATOR"}:
        raise ProbeError(
            f"DMID {args.mode} probe ended as {outcome}; evidence={public_path}"
        )
    if outcome == "CONTROL_PASS" and (
        health_after.get("ok") is not True or not cleanup_ok
    ):
        raise ProbeError(f"control did not close with exact final health; evidence={public_path}")
    return raw_path, public_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default=BRIDGE_HOST)
    parser.add_argument("--port", type=int, default=BRIDGE_PORT)
    parser.add_argument("--timeout", type=float, default=25.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    raw, public = collect(args)
    print(f"private={raw}")
    print(f"public={public}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
