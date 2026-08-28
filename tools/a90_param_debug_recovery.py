#!/usr/bin/env python3
"""Host-only recovery core for an ambiguous A90 ``param.debuglevel`` write.

This module deliberately stops at the recovery boundary.  It does not import
the A90 bridge, ADB, socket, subprocess, or any other device-facing helper.
The later live owner may use the fixed constants and the validated source
record from this module, but importing or calling the pure helpers here cannot
contact a device.

The source record is the durable journal written by
``a90_param_debug_transition.py``.  A recovery decision is valid only when
that journal proves one of the two fixed transitions was armed/dispatched,
the exact A90/``param`` binding was in force, replay was false, and
reconciliation is required.  A current image is classified only after its
complete size and fixed stable-range LOW/MID identity have been checked;
the retained full digest remains forensic evidence rather than a live pin.
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
import stat
from typing import Mapping, Sequence


# ---------------------------------------------------------------------------
# Immutable producer bindings
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]

TARGET_MODEL = "SM-A908N"
TARGET_SOC = "SM8150"
TARGET_BOOTLOADER = "A908NKSU5EWA3"
TARGET_RUNTIME = "v2321-usb-clean-identity-rodata"
TARGET_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"

PARAM_PARTNAME = "param"
PARAM_DEVNAME = "sda10"
PARAM_MAJOR = 8
PARAM_MINOR = 10
PARAM_SECTORS = 20_480
PARAM_PARTITION_BYTES = 0xA00000
PARAM_START_SECTOR = 125_080
PARAM_READ_ONLY = 0
PARAM_LOGICAL_BLOCK_SIZE = 4096
PARAM_CMDLINE_UPLOAD_OFFSET = "9438196"
PARAM_DEBUG_OFFSET = 0x900000
PARAM_DEBUG_SIZE = 4

# Param capture's stable identity excludes exactly the observed boot-cycle
# volatile byte ``[0,1)``; ownership is intentionally unknown.  Keep the
# scalar bindings here for the pure host recovery core;
# the implementation of ``stable_param_sha256`` is shared with the producer
# through a lazy import so importing this module remains free of transport
# (and socket) dependencies.
PARAM_VOLATILE_RANGES = ((0, 1),)
PARAM_STABLE_EXCLUDED_RANGES = PARAM_VOLATILE_RANGES
PARAM_STABLE_RANGE = (1, PARAM_PARTITION_BYTES)
PARAM_STABLE_RANGES = (PARAM_STABLE_RANGE,)
PARAM_STABLE_OFFSET = 1
PARAM_STABLE_END = PARAM_PARTITION_BYTES
PARAM_STABLE_SIZE = PARAM_PARTITION_BYTES - 1
PARAM_STABLE_MASK = {
    "excluded_ranges": [[0, 1]],
    "stable_ranges": [[1, PARAM_PARTITION_BYTES]],
    "stable_size": PARAM_STABLE_SIZE,
}
PARAM_STABLE_LOW_SHA256 = (
    "c0c7147418cf13145a44369a960c81647d347f317cb35baed1d85b286253c68a"
)
PARAM_STABLE_MID_SHA256 = (
    "9b85da06e4e4b1adb330c7169049a313ee5b0aa68014a2915a470f034c08f53f"
)
STABLE_LOW_SHA256 = PARAM_STABLE_LOW_SHA256
STABLE_MID_SHA256 = PARAM_STABLE_MID_SHA256
LOW_STABLE_SHA256 = PARAM_STABLE_LOW_SHA256
MID_STABLE_SHA256 = PARAM_STABLE_MID_SHA256
STABLE_MASK = PARAM_STABLE_MASK
VOLATILE_RANGES = PARAM_VOLATILE_RANGES
STABLE_RANGES = PARAM_STABLE_RANGES

LOW_BYTES = b"DLOW"
MID_BYTES = b"DMID"
DLOW_BYTES = LOW_BYTES

ROLLBACK_IMAGE = (
    REPO_ROOT
    / "evidence/private/verification-006-a90-param-capture-20260825-01/"
    "param--sda10.bin"
)
ROLLBACK_SHA256 = "1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345"
MID_SHA256 = "50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256"

# Aliases make the two pinned image roles explicit to callers without
# introducing a second source of values.
LOW_SHA256 = ROLLBACK_SHA256
LOW_IMAGE_SHA256 = ROLLBACK_SHA256
MID_IMAGE_SHA256 = MID_SHA256
ROLLBACK_SIZE = PARAM_PARTITION_BYTES
LOW_IMAGE_SIZE = PARAM_PARTITION_BYTES
MID_IMAGE_SIZE = PARAM_PARTITION_BYTES

DEVICE_NODE_PREFIX = "/dev/sdm855_mblab_"
DEVICE_NODE = DEVICE_NODE_PREFIX + PARAM_DEVNAME
PARAM_NODE_PATH = DEVICE_NODE
PAYLOAD_PATH = "/tmp/sdm855_mblab_param_debug_payload"
SMOKE_PATH = "/tmp/sdm855_mblab_param_debug_dd_smoke"

# This namespace is intentionally independent of every recovery experiment's
# output journal.  A source transition may be offered to exactly one recovery
# owner, even when that owner chooses a new experiment ID after a crash.
SOURCE_CONSUMPTION_DIRNAME = ".param-recovery-source-consumption"
SOURCE_CONSUMPTION_SCHEMA = "sdm855-a90-param-recovery-source-consumption-v1"
SOURCE_CLAIM_SUFFIX = ".claim.json"
SOURCE_CLAIM_REASON_ALREADY_LOW = "ALREADY_LOW_TERMINAL"
SOURCE_CLAIM_REASON_EFFECT_MARKER = "DLOW_EFFECT_MARKER"

DD_BLOCK_SIZE = 4
DD_COUNT = 1
DD_SEEK_BLOCKS = PARAM_DEBUG_OFFSET // DD_BLOCK_SIZE
DD_CONV = "notrunc,fsync"
DD_STATUS = "none"

# These are the exact values emitted by transition.fixed_dd_args() and the
# exact A90P1 argv stored in its durable journal.  The recovery effect is
# always the one fixed DLOW write, regardless of whether the source action was
# apply-mid or restore-low.
DLOW_PAYLOAD = LOW_BYTES
DLOW_PAYLOAD_BYTES = DLOW_PAYLOAD
DLOW_PAYLOAD_SIZE = len(DLOW_PAYLOAD)
DLOW_PAYLOAD_HEX = DLOW_PAYLOAD.hex()
DLOW_PAYLOAD_SHA256 = hashlib.sha256(DLOW_PAYLOAD).hexdigest()
MID_PAYLOAD = MID_BYTES
MID_PAYLOAD_SIZE = len(MID_PAYLOAD)
MID_PAYLOAD_HEX = MID_PAYLOAD.hex()
MID_PAYLOAD_SHA256 = hashlib.sha256(MID_PAYLOAD).hexdigest()
PAYLOAD_BASE64 = {
    LOW_BYTES: base64.b64encode(LOW_BYTES).decode("ascii"),
    MID_BYTES: base64.b64encode(MID_BYTES).decode("ascii"),
}
FIXED_DD_ARGS = (
    "dd",
    f"if={PAYLOAD_PATH}",
    f"of={DEVICE_NODE}",
    f"bs={DD_BLOCK_SIZE}",
    f"count={DD_COUNT}",
    f"seek={DD_SEEK_BLOCKS}",
    f"conv={DD_CONV}",
    f"status={DD_STATUS}",
)
FIXED_EFFECT_ARGV = ("run", "/bin/toybox", *FIXED_DD_ARGS)
DLOW_DD_ARGS = FIXED_DD_ARGS
DLOW_EFFECT_ARGV = FIXED_EFFECT_ARGV
ONE_WRITE_DD_ARGS = FIXED_DD_ARGS
ONE_WRITE_EFFECT_ARGV = FIXED_EFFECT_ARGV
FIXED_ONE_WRITE_ARGV = FIXED_EFFECT_ARGV

# JSON stores argv arrays as lists.  Keeping both tuple and list forms avoids
# accidental caller-controlled reconstruction while making exact comparisons
# straightforward.
FIXED_DD_ARGS_LIST = list(FIXED_DD_ARGS)
FIXED_EFFECT_ARGV_LIST = list(FIXED_EFFECT_ARGV)
DLOW_COMMAND = FIXED_EFFECT_ARGV
ONE_WRITE_COMMAND = FIXED_EFFECT_ARGV
FIXED_DD_COMMAND = FIXED_DD_ARGS
DLOW_COMMAND_LIST = list(FIXED_EFFECT_ARGV)
SMOKE_DD_ARGS = (
    "dd",
    f"if={PAYLOAD_PATH}",
    f"of={SMOKE_PATH}",
    f"bs={DD_BLOCK_SIZE}",
    f"count={DD_COUNT}",
    "seek=1",
    f"conv={DD_CONV}",
    f"status={DD_STATUS}",
)
SMOKE_DD_ARGS_LIST = list(SMOKE_DD_ARGS)
SMOKE_EXPECTED_SHA256 = {
    LOW_BYTES: hashlib.sha256(b"AAAA" + LOW_BYTES + b"CCCC").hexdigest(),
    MID_BYTES: hashlib.sha256(b"AAAA" + MID_BYTES + b"CCCC").hexdigest(),
}


# ---------------------------------------------------------------------------
# Durable schema/status bindings
# ---------------------------------------------------------------------------

SOURCE_SCHEMA = "sdm855-a90-param-debug-transition-journal-v1"
SOURCE_JOURNAL_SCHEMA = SOURCE_SCHEMA
TRANSITION_JOURNAL_SCHEMA = SOURCE_SCHEMA
RECOVERY_SOURCE_SCHEMA = SOURCE_SCHEMA

RECOVERY_JOURNAL_SCHEMA = "sdm855-a90-param-debug-recovery-journal-v1"
RECOVERY_PUBLIC_SCHEMA = "sdm855-a90-param-debug-recovery-public-v1"
RECOVERY_RECEIPT_SCHEMA = "sdm855-a90-param-debug-recovery-receipt-v1"
PRIVATE_RECEIPT_SCHEMA = RECOVERY_JOURNAL_SCHEMA
PUBLIC_RECEIPT_SCHEMA = RECOVERY_PUBLIC_SCHEMA
JOURNAL_SCHEMA = RECOVERY_JOURNAL_SCHEMA
PUBLIC_SCHEMA = RECOVERY_PUBLIC_SCHEMA
RECEIPT_SCHEMA = RECOVERY_RECEIPT_SCHEMA

AMBIGUOUS_STATUS = "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
SOURCE_AMBIGUOUS_STATUS = AMBIGUOUS_STATUS
EFFECT_ARMED_STATUS = "EFFECT_DISPATCH_STARTED"
EFFECT_RETURNED_STATUS = "EFFECT_RETURNED_VERIFYING_FULL_HASH"

ALREADY_LOW = "ALREADY_LOW"
RECOVERABLE_MID = "RECOVERABLE_MID"
RECOVERABLE_TORN = "RECOVERABLE_TORN"

RECOVERY_PREPARED = "RECOVERY_PREPARED"
RECOVERY_ALREADY_LOW = "RECOVERY_ALREADY_LOW"
RECOVERY_LOW_VERIFIED = "RECOVERY_LOW_VERIFIED"
RECOVERY_AMBIGUOUS = "RECOVERY_AMBIGUOUS_AFTER_EFFECT"
RECOVERY_RECONCILIATION_REQUIRED = "RECOVERY_RECONCILIATION_REQUIRED"

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_BYTES = MAX_SOURCE_BYTES
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SOURCE_CMDLINE_KEYS = (
    "androidboot.em.model",
    "androidboot.bootloader",
    "androidboot.debug_level",
    "androidboot.force_upload",
    "sec_debug.dump_sink",
    "androidboot.upload_offset",
)

__all__ = [
    "ALREADY_LOW",
    "AMBIGUOUS_STATUS",
    "DLOW_BYTES",
    "DLOW_PAYLOAD",
    "DLOW_PAYLOAD_HEX",
    "DLOW_PAYLOAD_SHA256",
    "DLOW_PAYLOAD_SIZE",
    "DLOW_COMMAND",
    "FIXED_DD_ARGS",
    "FIXED_EFFECT_ARGV",
    "LOW_BYTES",
    "LOW_IMAGE_SHA256",
    "LOW_STABLE_SHA256",
    "MAX_SOURCE_BYTES",
    "MID_BYTES",
    "MID_IMAGE_SHA256",
    "MID_SHA256",
    "MID_STABLE_SHA256",
    "PARAM_DEBUG_OFFSET",
    "PARAM_DEBUG_SIZE",
    "PARAM_PARTITION_BYTES",
    "PARAM_STABLE_EXCLUDED_RANGES",
    "PARAM_STABLE_OFFSET",
    "PARAM_STABLE_END",
    "PARAM_STABLE_MASK",
    "PARAM_STABLE_RANGE",
    "PARAM_STABLE_RANGES",
    "PARAM_STABLE_SIZE",
    "PARAM_STABLE_LOW_SHA256",
    "PARAM_STABLE_MID_SHA256",
    "PARAM_VOLATILE_RANGES",
    "STABLE_MASK",
    "STABLE_RANGES",
    "VOLATILE_RANGES",
    "RECOVERABLE_MID",
    "RECOVERABLE_TORN",
    "RECOVERY_JOURNAL_SCHEMA",
    "RECOVERY_PUBLIC_SCHEMA",
    "RECOVERY_RECEIPT_SCHEMA",
    "RECEIPT_SCHEMA",
    "RecoveryError",
    "ROLLBACK_IMAGE",
    "ROLLBACK_SHA256",
    "SOURCE_SCHEMA",
    "SOURCE_CMDLINE_KEYS",
    "JOURNAL_SCHEMA",
    "PUBLIC_SCHEMA",
    "TARGET_BOOTLOADER",
    "TARGET_KERNEL",
    "TARGET_MODEL",
    "TARGET_RUNTIME",
    "TARGET_SOC",
    "build_parser",
    "classify_live_image",
    "classify_param_image",
    "decode_fields",
    "collect",
    "derive_images",
    "execute",
    "load_pinned_low_image",
    "parse_source_journal",
    "pinned_images",
    "recovery_plan",
    "sha256",
    "stable_param_sha256",
    "stable_param_image_sha256",
    "stable_param_mask",
    "source_journal_path",
    "validate_source_journal",
    "validate_source_path",
    "validate_source",
    "safe_source_summary",
    "SOURCE_CONSUMPTION_SCHEMA",
    "SOURCE_CONSUMPTION_DIRNAME",
    "SOURCE_CLAIM_REASON_ALREADY_LOW",
    "SOURCE_CLAIM_REASON_EFFECT_MARKER",
    "source_consumption_claim_path",
    "source_claim_path",
    "source_consumption_claim_exists",
    "claim_source_consumption",
    "consume_source",
    "create_source_consumption_claim",
]


class ParamDebugRecoveryError(ValueError):
    """A fail-closed source, image, or recovery-core validation error."""


# Short aliases are useful to callers that share error handling with the
# existing A90 recovery owner.
RecoveryError = ParamDebugRecoveryError
ParamRecoveryError = ParamDebugRecoveryError


def sha256(data: bytes) -> str:
    """Return the SHA-256 digest of one in-memory byte string."""

    if not isinstance(data, bytes):
        raise ParamDebugRecoveryError("SHA-256 input must be bytes")
    return hashlib.sha256(data).hexdigest()


def stable_param_sha256(data: bytes) -> str:
    """Use the producer's exact stable-mask implementation without import IO."""

    try:
        from tools.a90_param_capture import stable_param_sha256 as producer_hash
    except ModuleNotFoundError:  # direct execution from tools/
        from a90_param_capture import stable_param_sha256 as producer_hash  # type: ignore
    try:
        return producer_hash(data)
    except ValueError as exc:
        raise ParamDebugRecoveryError(str(exc)) from exc


stable_param_image_sha256 = stable_param_sha256


def stable_param_mask() -> dict[str, object]:
    """Return a fresh copy of the producer's fixed range contract."""

    try:
        from tools.a90_param_capture import stable_param_mask as producer_mask
    except ModuleNotFoundError:  # direct execution from tools/
        from a90_param_capture import stable_param_mask as producer_mask  # type: ignore
    return producer_mask()


def decode_fields(data: bytes) -> dict[str, object]:
    """Delegate field decoding to the producer's exact byte-offset contract."""

    try:
        from tools.a90_param_capture import decode_fields as producer_decode
    except ModuleNotFoundError:  # direct execution from tools/
        from a90_param_capture import decode_fields as producer_decode  # type: ignore
    try:
        return producer_decode(data)
    except ValueError as exc:
        raise ParamDebugRecoveryError(str(exc)) from exc


def _expected_target() -> dict[str, str]:
    return {
        "model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
    }


def _require_exact(mapping: Mapping[str, object], key: str, expected: object, label: str) -> None:
    """Require exact JSON scalar/container type and value."""

    if key not in mapping:
        raise ParamDebugRecoveryError(f"{label} is missing required field {key!r}")
    actual = mapping[key]
    # ``bool`` is an ``int`` subclass; exact type prevents true from becoming
    # an accepted count/offset.
    if type(actual) is not type(expected) or actual != expected:
        raise ParamDebugRecoveryError(
            f"{label} field {key!r} is not exact: {actual!r} != {expected!r}"
        )


def _require_hash(value: object, expected: str, label: str) -> None:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None or value != expected:
        raise ParamDebugRecoveryError(f"{label} hash is not the pinned SHA-256")


def _require_hash_shape(value: object, label: str) -> str:
    """Require a retained full SHA-256 observation without pinning it."""

    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise ParamDebugRecoveryError(f"{label} hash is not an exact SHA-256 observation")
    return value


def _require_finite_tree(value: object, label: str = "JSON") -> None:
    """Defensive post-parse guard against non-finite values at any depth."""

    if isinstance(value, float) and not math.isfinite(value):
        raise ParamDebugRecoveryError(f"{label} contains non-finite JSON number")
    if isinstance(value, Mapping):
        for key, item in value.items():
            _require_finite_tree(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _require_finite_tree(item, f"{label}[{index}]")


# ---------------------------------------------------------------------------
# Stable, no-follow source reading
# ---------------------------------------------------------------------------

def _reject_symlink_components(path: Path, label: str = "path") -> None:
    """Reject a leaf or any lexical parent component that is a symlink."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(lexical.anchor or os.sep)
    while True:
        try:
            is_link = cursor.is_symlink()
        except OSError as exc:
            raise ParamDebugRecoveryError(
                f"{label} component cannot be inspected: {cursor}"
            ) from exc
        if is_link:
            raise ParamDebugRecoveryError(
                f"{label} component must not be a symlink: {cursor}"
            )
        if cursor == anchor:
            return
        cursor = cursor.parent


def _open_regular_nofollow(path: Path) -> int:
    """Open one path by walking every directory with ``O_NOFOLLOW``."""

    _reject_symlink_components(path, "source journal")
    absolute = Path(os.path.abspath(path))
    components = absolute.parts
    if not components:
        raise ParamDebugRecoveryError("source journal path is empty")

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(components[0], directory_flags)
    except OSError as exc:
        raise ParamDebugRecoveryError(
            f"source journal parent cannot be opened: {path}"
        ) from exc
    try:
        for component in components[1:-1]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            except OSError as exc:
                raise ParamDebugRecoveryError(
                    f"source journal parent cannot be opened: {path}"
                ) from exc
            os.close(parent_fd)
            parent_fd = next_fd
        leaf_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        leaf_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            return os.open(components[-1], leaf_flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ParamDebugRecoveryError(
                f"source journal cannot be opened: {path}"
            ) from exc
    finally:
        os.close(parent_fd)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _stable_bytes(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Read a bounded regular file through one stable no-follow descriptor."""

    try:
        _reject_symlink_components(path, label)
        temporary = path.with_name(path.name + ".tmp")
        if temporary.exists() or temporary.is_symlink():
            raise ParamDebugRecoveryError(
                f"{label} temporary sibling exists: {temporary}"
            )
        descriptor = _open_regular_nofollow(path)
    except ParamDebugRecoveryError:
        raise
    except OSError as exc:
        raise ParamDebugRecoveryError(f"{label} is unavailable: {path}") from exc

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ParamDebugRecoveryError(f"{label} is not a regular file")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise ParamDebugRecoveryError(
                f"{label} exceeds fixed bound {max_bytes} bytes"
            )

        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(descriptor, min(64 * 1024, max_bytes - total + 1))
            except OSError as exc:
                raise ParamDebugRecoveryError(f"{label} could not be read") from exc
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ParamDebugRecoveryError(
                    f"{label} exceeds fixed bound {max_bytes} bytes"
                )

        after = os.fstat(descriptor)
        if _identity(before) != _identity(after) or total != after.st_size:
            raise ParamDebugRecoveryError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ParamDebugRecoveryError(f"source journal contains duplicate key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ParamDebugRecoveryError(
        f"source journal contains non-finite JSON constant: {value}"
    )


def _decode_source_json(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except ParamDebugRecoveryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParamDebugRecoveryError(
            "source journal is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ParamDebugRecoveryError("source journal root is not an object")
    _require_finite_tree(value)
    return value


def _stable_source(path: Path) -> tuple[dict[str, object], bytes, str]:
    """Read, bound, parse, and hash one source transition journal."""

    checked = Path(path)
    raw = _stable_bytes(
        checked,
        max_bytes=MAX_SOURCE_BYTES,
        label="source journal",
    )
    value = _decode_source_json(raw)
    return value, raw, hashlib.sha256(raw).hexdigest()


def parse_source_journal(path: Path) -> tuple[dict[str, object], bytes, str]:
    """Public alias for the stable source-journal parser."""

    return _stable_source(Path(path))


read_source_journal = parse_source_journal
load_source_journal = parse_source_journal


def _path_under(path: Path, root: Path, label: str) -> Path:
    """Resolve a provenance path while refusing symlink components."""

    source = path if path.is_absolute() else Path.cwd() / path
    boundary = root if root.is_absolute() else Path.cwd() / root
    _reject_symlink_components(source, label)
    _reject_symlink_components(boundary, f"{label} root")
    source_abs = Path(os.path.abspath(source))
    boundary_abs = Path(os.path.abspath(boundary))
    try:
        source_abs.relative_to(boundary_abs)
    except ValueError as exc:
        raise ParamDebugRecoveryError(
            f"{label} is outside the fixed evidence root"
        ) from exc
    return source_abs


def source_journal_path(
    root: Path = REPO_ROOT, experiment_id: str | None = None
) -> Path:
    """Return the producer's fixed journal path for one safe experiment ID.

    This is a programmatic convenience for the later owner.  It is not
    exposed as a command-line path selector.
    """

    if type(experiment_id) is not str or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise ParamDebugRecoveryError("invalid source experiment ID")
    return Path(root) / "evidence" / "private" / f"{experiment_id}.journal.json"


# ---------------------------------------------------------------------------
# Exact source-journal validator
# ---------------------------------------------------------------------------

def _validate_target(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ParamDebugRecoveryError(f"{label} is not an object")
    expected = _expected_target()
    for key, item in expected.items():
        _require_exact(value, key, item, label)
    return dict(expected)


def _expected_cmdline_relevant(action: str) -> dict[str, object]:
    debug_level: object = "0x4f4c" if action == "apply-mid" else {"0x4f4c", "0x494d"}
    return {
        "androidboot.em.model": TARGET_MODEL,
        "androidboot.bootloader": TARGET_BOOTLOADER,
        "androidboot.debug_level": debug_level,
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
        "androidboot.upload_offset": PARAM_CMDLINE_UPLOAD_OFFSET,
    }


def _validate_cmdline_before(
    value: object, action: str
) -> tuple[dict[str, str], dict[str, str]]:
    """Validate the producer's exact pre-effect cmdline and return safe fields."""

    if not isinstance(value, Mapping):
        raise ParamDebugRecoveryError("source cmdline_before is not an object")
    if any(type(key) is not str or type(item) is not str for key, item in value.items()):
        raise ParamDebugRecoveryError("source cmdline_before contains a non-string field")
    full = dict(value)
    relevant_expected = _expected_cmdline_relevant(action)
    for key, expected in relevant_expected.items():
        if key == "androidboot.debug_level" and isinstance(expected, set):
            actual = value.get(key)
            if type(actual) is not str or actual not in expected:
                raise ParamDebugRecoveryError(
                    "source cmdline_before debug level is not an allowed exact value"
                )
        else:
            _require_exact(value, key, expected, "source cmdline_before")
    relevant = {key: str(value[key]) for key in relevant_expected}
    return full, relevant


def _validate_download_mode_before(value: object) -> str:
    _require_exact({"download_mode_before": value}, "download_mode_before", "1", "source")
    return "1"


def _validate_partition(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ParamDebugRecoveryError("source partition binding is not an object")
    expected: dict[str, object] = {
        "partname": PARAM_PARTNAME,
        "devname": PARAM_DEVNAME,
        "major": PARAM_MAJOR,
        "minor": PARAM_MINOR,
        "sectors": PARAM_SECTORS,
        "byte_size": PARAM_PARTITION_BYTES,
        "read_only": PARAM_READ_ONLY,
        "logical_block_size": PARAM_LOGICAL_BLOCK_SIZE,
        "start_sector": PARAM_START_SECTOR,
    }
    for key, item in expected.items():
        _require_exact(value, key, item, "source partition")
    return dict(expected)


def _transition_expectation(action: str) -> dict[str, object]:
    if action == "apply-mid":
        before, after = LOW_BYTES, MID_BYTES
        before_label, after_label = "LOW", "MID"
        before_hash, after_hash = ROLLBACK_SHA256, MID_SHA256
        before_stable, after_stable = PARAM_STABLE_LOW_SHA256, PARAM_STABLE_MID_SHA256
    elif action == "restore-low":
        before, after = MID_BYTES, LOW_BYTES
        before_label, after_label = "MID", "LOW"
        before_hash, after_hash = MID_SHA256, ROLLBACK_SHA256
        before_stable, after_stable = PARAM_STABLE_MID_SHA256, PARAM_STABLE_LOW_SHA256
    else:
        raise ParamDebugRecoveryError(
            "source action must be exactly apply-mid or restore-low"
        )
    return {
        "partition_offset": f"0x{PARAM_DEBUG_OFFSET:06x}",
        "size": PARAM_DEBUG_SIZE,
        "before_label": before_label,
        "after_label": after_label,
        "before_bytes_hex": before.hex(),
        "after_bytes_hex": after.hex(),
        "before_sha256": before_hash,
        "after_sha256": after_hash,
        "before_stable_sha256": before_stable,
        "after_stable_sha256": after_stable,
        "stable_mask": {
            "excluded_ranges": [[0, 1]],
            "stable_ranges": [[1, PARAM_PARTITION_BYTES]],
            "stable_size": PARAM_STABLE_SIZE,
        },
    }


def _validate_transition(value: object, action: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ParamDebugRecoveryError("source transition binding is not an object")
    expected = _transition_expectation(action)
    for key, item in expected.items():
        _require_exact(value, key, item, "source transition")
    # Ensure the transition hash pins are syntactically complete even though
    # _require_exact already binds their values.
    _require_hash(value["before_sha256"], expected["before_sha256"], "before image")
    _require_hash(value["after_sha256"], expected["after_sha256"], "after image")
    _require_hash(
        value["before_stable_sha256"],
        expected["before_stable_sha256"],
        "before stable image",
    )
    _require_hash(
        value["after_stable_sha256"],
        expected["after_stable_sha256"],
        "after stable image",
    )
    return dict(expected)


def _validate_effect_argv(value: object) -> list[str]:
    if type(value) is not list or value != FIXED_EFFECT_ARGV_LIST:
        raise ParamDebugRecoveryError(
            "source effect argv is not the fixed one-write toybox dd command"
        )
    if any(type(item) is not str for item in value):
        raise ParamDebugRecoveryError("source effect argv contains a non-string")
    return list(FIXED_EFFECT_ARGV_LIST)


def _action_payload(action: str) -> bytes:
    if action == "apply-mid":
        return MID_BYTES
    if action == "restore-low":
        return LOW_BYTES
    raise ParamDebugRecoveryError(
        "source action must be exactly apply-mid or restore-low"
    )


def _validate_payload(value: object, action: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ParamDebugRecoveryError("source payload record is not an object")
    payload = _action_payload(action)
    expected = {
        "path": PAYLOAD_PATH,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "readback_base64": PAYLOAD_BASE64[payload],
    }
    for key, item in expected.items():
        _require_exact(value, key, item, "source payload")
    _require_hash(value["sha256"], expected["sha256"], "source payload")
    return dict(expected)


def _validate_smoke(value: object, action: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ParamDebugRecoveryError(
            "source regular_file_dd_smoke record is not an object"
        )
    payload = _action_payload(action)
    expected_hash = SMOKE_EXPECTED_SHA256[payload]
    expected = {
        "args": list(SMOKE_DD_ARGS_LIST),
        "passed": True,
        "expected_sha256": expected_hash,
        "readback_sha256": expected_hash,
    }
    for key, item in expected.items():
        _require_exact(value, key, item, "source regular_file_dd_smoke")
    _require_hash(value["expected_sha256"], expected_hash, "source smoke expected")
    _require_hash(value["readback_sha256"], expected_hash, "source smoke readback")
    return dict(expected)


def validate_source_journal(source: Mapping[str, object]) -> dict[str, object]:
    """Validate one ambiguous transition journal and return a safe summary.

    Both current producer forms are accepted: the existing transition writer
    durably records ``effect_dispatched=true`` before calling the fixed command
    but does not serialize its local ``effect_armed`` variable; a newer writer
    may include ``effect_armed=true`` and ``effect_dispatched_count=1``.  If
    either optional field is present, it must be exact.  The fixed ambiguous
    status, argv, dispatch marker, complete device-before/full observation,
    stable preimage identity, exact staged payload, and successful
    regular-file ``dd`` smoke provide the durable arm proof for the current
    producer.
    """

    if not isinstance(source, Mapping):
        raise ParamDebugRecoveryError("source journal root is not an object")
    _require_exact(source, "schema", SOURCE_SCHEMA, "source journal")
    _require_exact(source, "status", AMBIGUOUS_STATUS, "source journal")
    action = source.get("action")
    if type(action) is not str or action not in {"apply-mid", "restore-low"}:
        raise ParamDebugRecoveryError(
            "source action must be exactly apply-mid or restore-low"
        )

    # The current transition producer writes ``target_verified`` in its
    # preflight revision but reconstructs the final journal without carrying
    # that convenience flag forward.  The exact target and expected_target
    # objects below are the durable proof; if a newer producer retains the
    # flag, it must still be true.
    if "target_verified" in source:
        _require_exact(source, "target_verified", True, "source journal")
    # The transition writer's final journal is reconstructed from the
    # preflight state and therefore does not retain ``expected_target``.  The
    # exact observed target below is sufficient because it is checked against
    # the same immutable binding; if a newer producer retains the redundant
    # object, validate it as well.
    if "expected_target" in source:
        expected_target = _validate_target(source.get("expected_target"), "expected target")
    else:
        expected_target = _expected_target()
    target = _validate_target(source.get("target"), "observed target")
    cmdline_before, cmdline_relevant = _validate_cmdline_before(
        source.get("cmdline_before"), action
    )
    download_mode_before = _validate_download_mode_before(
        source.get("download_mode_before")
    )
    partition = _validate_partition(source.get("partition"))
    transition = _validate_transition(source.get("transition"), action)
    # The full digest remains private forensic evidence, but byte 0 is
    # intentionally volatile and therefore must not be a source eligibility
    # pin.  Stable preimage/hash/mask below carry the causal identity.
    _require_hash_shape(source.get("device_sha256_before"), "source device-before")
    _require_hash(
        source.get("device_stable_sha256_before"),
        transition["before_stable_sha256"],
        "source stable device-before",
    )
    stable_mask = source.get("stable_mask")
    if stable_mask != transition["stable_mask"]:
        raise ParamDebugRecoveryError("source stable mask is not the fixed [0,1) exclusion")
    stable_range = source.get("stable_range")
    expected_stable_range = {
        "start": PARAM_STABLE_OFFSET,
        "end": PARAM_STABLE_END,
        "size": PARAM_STABLE_SIZE,
        "sha256": transition["before_stable_sha256"],
    }
    if stable_range != expected_stable_range:
        raise ParamDebugRecoveryError("source stable range/hash is not exact")
    volatile_byte0 = source.get("volatile_byte0_before")
    if type(volatile_byte0) is not int or not 0 <= volatile_byte0 <= 255:
        raise ParamDebugRecoveryError("source volatile byte-0 observation is not exact")
    payload = _validate_payload(source.get("payload"), action)
    smoke = _validate_smoke(source.get("regular_file_dd_smoke"), action)
    effect_argv = _validate_effect_argv(source.get("effect_argv"))

    _require_exact(source, "effect_dispatched", True, "source journal")
    _require_exact(source, "effect_replayed", False, "source journal")
    _require_exact(source, "reconcile_required", True, "source journal")

    # The producer defers cleanup whenever the effect is armed but its outcome
    # is not proved.  Requiring this closes the path where a successful journal
    # is accidentally offered as an ambiguous recovery source.
    _require_exact(source, "cleanup_deferred", True, "source journal")

    if "effect_armed" in source:
        _require_exact(source, "effect_armed", True, "source journal")
    if "effect_dispatched_count" in source:
        _require_exact(source, "effect_dispatched_count", 1, "source journal")
    if "dispatch_count" in source:
        _require_exact(source, "dispatch_count", 1, "source journal")
    if "automatic_retries" in source:
        _require_exact(source, "automatic_retries", False, "source journal")

    experiment_id = source.get("experiment_id")
    if type(experiment_id) is not str or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise ParamDebugRecoveryError("source experiment_id is not a safe fixed identifier")

    return {
        "schema": SOURCE_SCHEMA,
        "experiment_id": experiment_id,
        "action": action,
        "status": AMBIGUOUS_STATUS,
        "target_verified": True,
        "expected_target": expected_target,
        "target": target,
        "cmdline_before": cmdline_before,
        "cmdline_relevant": cmdline_relevant,
        "download_mode_before": download_mode_before,
        "partition": partition,
        "transition": transition,
        "device_sha256_before": _require_hash_shape(
            source.get("device_sha256_before"), "source device-before"
        ),
        "device_stable_sha256_before": transition["before_stable_sha256"],
        "stable_mask": dict(transition["stable_mask"]),
        "stable_range": dict(expected_stable_range),
        "volatile_byte0_before": volatile_byte0,
        "payload": payload,
        "regular_file_dd_smoke": smoke,
        "effect_argv": effect_argv,
        "effect_armed": True,
        "effect_dispatched": True,
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "cleanup_deferred": True,
        "reconcile_required": True,
    }


_validate_source = validate_source_journal
validate_ambiguous_journal = validate_source_journal


def safe_source_summary(source: Mapping[str, object]) -> dict[str, object]:
    """Return only non-sensitive bindings needed by the live owner.

    The full ``cmdline_before`` remains available in the private validation
    result for an exact same-boot comparison.  This summary deliberately
    retains only the target, GPT geometry, relevant cmdline fields, action,
    hashes, and fixed recovery payload evidence; it never exposes raw serial
    or unrelated cmdline values.
    """

    validated = validate_source_journal(source)
    result: dict[str, object] = {
        "schema": validated["schema"],
        "experiment_id": validated["experiment_id"],
        "action": validated["action"],
        "target": dict(validated["target"]),
        "partition": dict(validated["partition"]),
        "cmdline_relevant": dict(validated["cmdline_relevant"]),
        "download_mode_before": validated["download_mode_before"],
        "device_sha256_before": validated["device_sha256_before"],
        "device_stable_sha256_before": validated["device_stable_sha256_before"],
        "stable_mask": dict(validated["stable_mask"]),
        "stable_range": dict(validated["stable_range"]),
        "volatile_byte0_before": validated["volatile_byte0_before"],
        "payload": dict(validated["payload"]),
        "regular_file_dd_smoke": dict(validated["regular_file_dd_smoke"]),
        "effect_argv": list(validated["effect_argv"]),
        "effect_armed": validated["effect_armed"],
        "effect_dispatched": validated["effect_dispatched"],
        "effect_dispatched_count": validated["effect_dispatched_count"],
        "effect_replayed": validated["effect_replayed"],
        "reconcile_required": validated["reconcile_required"],
    }
    # File-backed validation adds these exact provenance bindings; retain them
    # when present so the live owner can construct its one-shot source claim.
    for key in ("source_path", "source_sha256", "source_size", "source_identity"):
        if key in validated:
            result[key] = validated[key]
    return result


source_summary = safe_source_summary


def validate_source_path(path: Path, *, root: Path | None = None) -> dict[str, object]:
    """Read and validate a source journal, returning a redacted summary."""

    source_path = Path(path)
    if root is not None:
        source_path = _path_under(
            source_path,
            Path(root) / "evidence" / "private",
            "source journal",
        )
    source, raw, digest = _stable_source(source_path)
    summary = validate_source_journal(source)
    # Capture the descriptor identity used for the validated bytes.  The
    # identity is retained in the one-shot source claim so a path replacement
    # cannot silently become a new recovery authorization.
    try:
        descriptor = _open_regular_nofollow(source_path)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size != len(raw):
                raise ParamDebugRecoveryError(
                    "source journal identity changed after validation"
                )
            source_identity = {
                "st_dev": info.st_dev,
                "st_ino": info.st_ino,
                "st_mode": info.st_mode,
                "st_size": info.st_size,
                "st_mtime_ns": info.st_mtime_ns,
                "st_ctime_ns": info.st_ctime_ns,
            }
        finally:
            os.close(descriptor)
    except ParamDebugRecoveryError:
        raise
    except OSError as exc:
        raise ParamDebugRecoveryError(
            f"source journal identity cannot be retained: {source_path}"
        ) from exc
    # Re-read after taking the descriptor identity.  If the path was replaced
    # or edited between the first bounded parse and this identity snapshot,
    # reject rather than issuing a claim for bytes that were never validated
    # under one identity/hash pair.
    source_again, raw_again, digest_again = _stable_source(source_path)
    if (
        digest_again != digest
        or raw_again != raw
        or source_again != source
        or source_identity["st_size"] != len(raw_again)
    ):
        raise ParamDebugRecoveryError(
            "source journal changed while its claim identity was being captured"
        )
    try:
        descriptor_again = _open_regular_nofollow(source_path)
        try:
            info_again = os.fstat(descriptor_again)
            identity_again = {
                "st_dev": info_again.st_dev,
                "st_ino": info_again.st_ino,
                "st_mode": info_again.st_mode,
                "st_size": info_again.st_size,
                "st_mtime_ns": info_again.st_mtime_ns,
                "st_ctime_ns": info_again.st_ctime_ns,
            }
        finally:
            os.close(descriptor_again)
    except OSError as exc:
        raise ParamDebugRecoveryError(
            "source journal identity cannot be rechecked"
        ) from exc
    if identity_again != source_identity:
        raise ParamDebugRecoveryError(
            "source journal identity changed while its claim was being captured"
        )
    summary.update(
        {
            "source_path": str(source_path),
            "source_sha256": digest,
            "source_size": len(raw),
            "source_identity": source_identity,
        }
    )
    return summary


def _source_claim_binding(source_summary: Mapping[str, object]) -> dict[str, object]:
    """Validate the source fields used to construct a one-shot claim key."""

    if not isinstance(source_summary, Mapping):
        raise ParamDebugRecoveryError("source claim input is not an object")
    _require_exact(source_summary, "schema", SOURCE_SCHEMA, "source claim")
    _require_exact(source_summary, "effect_replayed", False, "source claim")
    _require_exact(source_summary, "effect_dispatched", True, "source claim")
    _require_exact(source_summary, "reconcile_required", True, "source claim")
    source_id = source_summary.get("experiment_id")
    if type(source_id) is not str or SAFE_ID_RE.fullmatch(source_id) is None:
        raise ParamDebugRecoveryError("source claim has an invalid source experiment ID")
    source_hash = source_summary.get("source_sha256")
    if type(source_hash) is not str or SHA256_RE.fullmatch(source_hash) is None:
        raise ParamDebugRecoveryError("source claim lacks a validated source SHA-256")
    source_size = source_summary.get("source_size")
    if type(source_size) is not int or source_size <= 0 or source_size > MAX_SOURCE_BYTES:
        raise ParamDebugRecoveryError("source claim has an invalid source size")
    identity = source_summary.get("source_identity")
    if not isinstance(identity, Mapping):
        raise ParamDebugRecoveryError("source claim lacks a validated source identity")
    expected_identity_keys = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    retained_identity: dict[str, int] = {}
    for key in expected_identity_keys:
        value = identity.get(key)
        if type(value) is not int or value < 0:
            raise ParamDebugRecoveryError(
                f"source claim identity field is invalid: {key}"
            )
        retained_identity[key] = value
    if retained_identity["st_size"] != source_size:
        raise ParamDebugRecoveryError("source claim identity size differs from source bytes")
    source_path = source_summary.get("source_path")
    if type(source_path) is not str or not source_path:
        raise ParamDebugRecoveryError("source claim lacks a validated source path")
    _require_hash(
        source_summary.get("device_stable_sha256_before"),
        source_summary.get("device_stable_sha256_before"),
        "source stable preimage",
    )
    if source_summary.get("stable_mask") != PARAM_STABLE_MASK:
        raise ParamDebugRecoveryError("source claim stable mask is not fixed")
    return {
        "source_experiment_id": source_id,
        "source_journal": Path(source_path).name,
        "source_journal_sha256": source_hash,
        "source_journal_size": source_size,
        "source_identity": retained_identity,
        "source_journal_identity": retained_identity,
        "preimage_full_sha256": source_summary["device_sha256_before"],
        "stable_preimage_sha256": source_summary["device_stable_sha256_before"],
        "stable_mask": {
            "excluded_ranges": [[0, 1]],
            "stable_ranges": [[1, PARAM_PARTITION_BYTES]],
            "stable_size": PARAM_STABLE_SIZE,
        },
    }


def _revalidate_source_binding(
    source_summary: Mapping[str, object],
    binding: Mapping[str, object],
    *,
    root: Path | None = None,
) -> None:
    """Re-read the validated source immediately before creating its claim.

    A recovery run can spend substantial time between source validation and a
    terminal close.  Requiring the same bytes, hash, and descriptor identity at
    the O_EXCL boundary prevents an in-place journal edit or inode replacement
    from being silently converted into a new recovery authorization.
    """

    source_path_value = source_summary.get("source_path")
    if type(source_path_value) is not str or not source_path_value:
        raise ParamDebugRecoveryError("source claim lacks a revalidatable source path")
    source_path = Path(source_path_value)
    source_id = binding.get("source_experiment_id")
    base = Path(REPO_ROOT if root is None else root)
    base_absolute = base if base.is_absolute() else Path.cwd() / base
    expected_source = base_absolute / "evidence" / "private" / (
        f"{source_id}.journal.json"
    )
    source_absolute = source_path if source_path.is_absolute() else Path.cwd() / source_path
    if source_absolute != expected_source:
        raise ParamDebugRecoveryError(
            "source claim path is not the fixed path derived from its experiment ID"
        )
    try:
        current, raw, digest = _stable_source(source_path)
        descriptor = _open_regular_nofollow(source_path)
        try:
            info = os.fstat(descriptor)
            current_identity = {
                "st_dev": info.st_dev,
                "st_ino": info.st_ino,
                "st_mode": info.st_mode,
                "st_size": info.st_size,
                "st_mtime_ns": info.st_mtime_ns,
                "st_ctime_ns": info.st_ctime_ns,
            }
        finally:
            os.close(descriptor)
    except ParamDebugRecoveryError:
        raise
    except OSError as exc:
        raise ParamDebugRecoveryError(
            f"source journal cannot be revalidated before claim: {source_path}"
        ) from exc
    if digest != binding.get("source_journal_sha256"):
        raise ParamDebugRecoveryError("source journal hash changed before claim")
    if len(raw) != binding.get("source_journal_size"):
        raise ParamDebugRecoveryError("source journal size changed before claim")
    if current_identity != binding.get("source_identity"):
        raise ParamDebugRecoveryError("source journal identity changed before claim")
    # The hash comparison above binds the complete JSON bytes.  Validate the
    # parsed object as well so a monkeypatched/hash-inconsistent source reader
    # cannot bypass the source schema at this boundary.
    validate_source_journal(current)


def source_consumption_claim_path(
    source_summary: Mapping[str, object], *, root: Path | None = None
) -> Path:
    """Return the fixed repo-root O_EXCL claim path for one source journal."""

    binding = _source_claim_binding(source_summary)
    base = Path(REPO_ROOT if root is None else root)
    base_absolute = base if base.is_absolute() else Path.cwd() / base
    _reject_symlink_components(base, "source-consumption repository root")
    expected_source = base_absolute / "evidence" / "private" / (
        f"{binding['source_experiment_id']}.journal.json"
    )
    actual_source = Path(str(source_summary["source_path"]))
    if not actual_source.is_absolute():
        actual_source = Path.cwd() / actual_source
    if actual_source != expected_source:
        raise ParamDebugRecoveryError(
            "source journal path is not the fixed path derived from its experiment ID"
        )
    _reject_symlink_components(expected_source, "source journal")
    directory = base / "evidence" / "private" / SOURCE_CONSUMPTION_DIRNAME
    _reject_symlink_components(directory, "source-consumption directory")
    # The canonical source experiment/path, not a caller-selected recovery ID
    # or mutable raw-JSON hash, is the namespace key.  The validated hash and
    # descriptor identity live in the claim contents; semantically equivalent
    # reserializations of one source therefore still collide on this claim.
    return directory / f"{binding['source_experiment_id']}{SOURCE_CLAIM_SUFFIX}"


def source_consumption_claim_exists(
    source_summary: Mapping[str, object], *, root: Path | None = None
) -> bool:
    """Check for an existing claim without following a symlink."""

    path = source_consumption_claim_path(source_summary, root=root)
    if path.is_symlink():
        raise ParamDebugRecoveryError(
            f"source-consumption claim is a symlink: {path}"
        )
    return path.exists()


def claim_source_consumption(
    source_summary: Mapping[str, object],
    recovery_experiment_id: str,
    *,
    root: Path | None = None,
    reason: str,
) -> dict[str, object]:
    """Atomically consume a validated source journal exactly once.

    ``reason`` is deliberately restricted to the two terminal boundaries:
    the zero-write ALREADY_LOW close and the DLOW effect marker.  The claim is
    created with O_EXCL/no-follow and left in place on a write/fsync failure;
    a crash therefore fails closed and cannot authorize replay.
    """

    binding = _source_claim_binding(source_summary)
    if type(recovery_experiment_id) is not str or SAFE_ID_RE.fullmatch(
        recovery_experiment_id
    ) is None:
        raise ParamDebugRecoveryError("source claim has an invalid recovery experiment ID")
    if reason not in {
        SOURCE_CLAIM_REASON_ALREADY_LOW,
        SOURCE_CLAIM_REASON_EFFECT_MARKER,
    }:
        raise ParamDebugRecoveryError("source claim reason is not a fixed terminal boundary")
    # Revalidate the source identity/hash immediately before the O_EXCL claim.
    # This is intentionally before creating the claim directory or file, so a
    # pre-claim source mutation remains retryable rather than being recorded as
    # a consumed source.
    _revalidate_source_binding(source_summary, binding, root=root)
    path = source_consumption_claim_path(source_summary, root=root)
    directory = path.parent
    _reject_symlink_components(directory, "source-consumption directory")
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ParamDebugRecoveryError(
                "source-consumption directory is not a regular directory"
            )
        os.chmod(directory, 0o700)
    except ParamDebugRecoveryError:
        raise
    except OSError as exc:
        raise ParamDebugRecoveryError(
            f"source-consumption directory cannot be secured: {directory}"
        ) from exc

    created = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    claim = {
        "schema": SOURCE_CONSUMPTION_SCHEMA,
        **binding,
        "recovery_experiment_id": recovery_experiment_id,
        "reason": reason,
        "effect_replayed": False,
        "created_utc": created,
    }
    data = json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        # Hold an O_NOFOLLOW directory descriptor while opening the leaf.  A
        # path-only open would still permit a parent-directory replacement
        # race after the lexical symlink checks above.
        directory_fd = os.open(directory, directory_flags)
        descriptor = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError as exc:
        try:
            os.close(directory_fd)
        except (OSError, UnboundLocalError):
            pass
        raise ParamDebugRecoveryError(
            "source journal has already been consumed; recovery replay is forbidden"
        ) from exc
    except OSError as exc:
        try:
            os.close(directory_fd)
        except (OSError, UnboundLocalError):
            pass
        raise ParamDebugRecoveryError(
            f"source-consumption claim cannot be created: {path}"
        ) from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ParamDebugRecoveryError(
                    "source-consumption claim write made no progress"
                )
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        # Do not unlink a claim after creation.  A partial claim is evidence of
        # a crash at the no-replay boundary and must remain a fail-closed lock.
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.close(directory_fd)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        # Keep the claim; directory-fsync failure is an ambiguous host-side
        # close and must not make the source reusable.
        try:
            os.close(directory_fd)
        except OSError:
            pass
        raise ParamDebugRecoveryError(
            f"source-consumption claim directory fsync failed: {directory}"
        ) from exc
    else:
        os.close(directory_fd)
    return {
        "filename": path.name,
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        **binding,
        "recovery_experiment_id": recovery_experiment_id,
        "reason": reason,
        "effect_replayed": False,
        "created_utc": created,
    }


# Descriptive aliases used by owners/tests that call the boundary a consume
# operation rather than a claim operation.
consume_source = claim_source_consumption
create_source_consumption_claim = claim_source_consumption
source_claim_path = source_consumption_claim_path


def validate_source(
    source: Mapping[str, object] | Path,
    *,
    root: Path | None = None,
) -> dict[str, object]:
    """Validate either an already parsed source object or a journal path."""

    if isinstance(source, Mapping):
        return validate_source_journal(source)
    if isinstance(source, Path):
        return validate_source_path(source, root=root)
    raise ParamDebugRecoveryError("source journal input must be a mapping or Path")


# ---------------------------------------------------------------------------
# Pure current-image classification
# ---------------------------------------------------------------------------

def _stable_image_bytes(path: Path | None = None) -> bytes:
    if path is None:
        path = ROLLBACK_IMAGE
    raw = _stable_bytes(
        Path(path),
        max_bytes=PARAM_PARTITION_BYTES,
        label="pinned LOW image",
    )
    if len(raw) != PARAM_PARTITION_BYTES:
        raise ParamDebugRecoveryError("pinned LOW image is not exactly 10 MiB")
    if sha256(raw) != ROLLBACK_SHA256:
        raise ParamDebugRecoveryError("pinned LOW image SHA-256 differs from the pin")
    if stable_param_sha256(raw) != PARAM_STABLE_LOW_SHA256:
        raise ParamDebugRecoveryError(
            "pinned LOW image stable SHA-256 differs from the fixed mask pin"
        )
    if raw[PARAM_DEBUG_OFFSET : PARAM_DEBUG_OFFSET + PARAM_DEBUG_SIZE] != LOW_BYTES:
        raise ParamDebugRecoveryError("pinned LOW image lacks DLOW at 0x900000")
    return raw


def pinned_images(path: Path | None = None) -> tuple[bytes, bytes]:
    """Load and verify the exact LOW artifact and host-derived MID image."""

    low = _stable_image_bytes(None if path is None else Path(path))
    mid = bytearray(low)
    mid[PARAM_DEBUG_OFFSET : PARAM_DEBUG_OFFSET + PARAM_DEBUG_SIZE] = MID_BYTES
    mid_bytes = bytes(mid)
    if sha256(mid_bytes) != MID_SHA256:
        raise ParamDebugRecoveryError("host-derived MID image SHA-256 differs from the pin")
    if stable_param_sha256(mid_bytes) != PARAM_STABLE_MID_SHA256:
        raise ParamDebugRecoveryError(
            "host-derived MID image stable SHA-256 differs from the fixed mask pin"
        )
    return low, mid_bytes


def derive_images(path: Path | None = None) -> tuple[bytes, bytes]:
    """Compatibility alias matching the transition producer's image helper."""

    return pinned_images(path)


def load_pinned_low_image(path: Path | None = None) -> bytes:
    return pinned_images(path)[0]


def classify_live_image(image: bytes) -> str:
    """Classify a complete live ``param`` image without any device access.

    ``ALREADY_LOW`` and ``RECOVERABLE_MID`` require the exact four-byte field
    and the fixed stable-range identity.  Byte ``[0,1)`` is retained as an
    observed boot-cycle volatile value and is not part of that identity.  Any
    other field value is ``RECOVERABLE_TORN`` only when every other stable byte
    is byte-identical to the pinned LOW image.  A wrong-size image, a wrong
    stable-range byte, or a corrupt pinned artifact is a hard refusal.
    """

    if type(image) is not bytes:
        raise ParamDebugRecoveryError("live param image must be bytes")
    if len(image) != PARAM_PARTITION_BYTES:
        raise ParamDebugRecoveryError(
            f"live param image size {len(image)} != {PARAM_PARTITION_BYTES}"
        )

    low, mid = pinned_images()
    start = PARAM_DEBUG_OFFSET
    end = start + PARAM_DEBUG_SIZE
    # Byte 0 is deliberately excluded from the semantic image identity.  All
    # remaining bytes, including the four-byte debug field, must match one of
    # the fixed stable LOW/MID images or the image is refused as unrelated.
    if (
        image[PARAM_STABLE_OFFSET:start] != low[PARAM_STABLE_OFFSET:start]
        or image[end:] != low[end:]
    ):
        raise ParamDebugRecoveryError(
            "live param image differs in the stable range outside the fixed 0x900000..0x900004 field"
        )

    field = image[start:end]
    stable_digest = stable_param_sha256(image)
    if field == LOW_BYTES:
        if stable_digest != PARAM_STABLE_LOW_SHA256:
            raise ParamDebugRecoveryError(
                "DLOW live image does not match the fixed stable LOW hash"
            )
        return ALREADY_LOW
    if field == MID_BYTES:
        if stable_digest != PARAM_STABLE_MID_SHA256:
            raise ParamDebugRecoveryError(
                "DMID live image does not match the fixed stable MID hash"
            )
        return RECOVERABLE_MID
    return RECOVERABLE_TORN


classify_param_image = classify_live_image
classify = classify_live_image


def recovery_plan(
    source: Mapping[str, object],
    live_image: bytes | None = None,
) -> dict[str, object]:
    """Build a host-only recovery plan from a source journal and image.

    No effect is dispatched here.  ``live_image`` is optional so the live
    owner can first validate provenance and then classify a read it obtained
    through its own exact transport boundary.
    """

    validated = validate_source_journal(source)
    classification = None if live_image is None else classify_live_image(live_image)
    return {
        "schema": RECOVERY_JOURNAL_SCHEMA,
        "source_schema": SOURCE_SCHEMA,
        "source_experiment_id": validated["experiment_id"],
        "source_action": validated["action"],
        "target": validated["target"],
        "partition": validated["partition"],
        "source_device_sha256_before": validated["device_sha256_before"],
        "source_device_stable_sha256_before": validated[
            "device_stable_sha256_before"
        ],
        "stable_mask": dict(validated["stable_mask"]),
        "payload": {
            "bytes_hex": DLOW_PAYLOAD_HEX,
            "size": DLOW_PAYLOAD_SIZE,
            "sha256": DLOW_PAYLOAD_SHA256,
        },
        "effect_argv": list(FIXED_EFFECT_ARGV_LIST),
        "classification": classification,
        "effect_dispatched": False,
        "effect_dispatched_count": 0,
        "effect_replayed": False,
        # LOW is already the pinned recovery state.  MID, a torn four-byte
        # field, and an as-yet-unread image all remain pending the fixed DLOW
        # recovery/reconciliation path; none may be treated as closed.
        "reconcile_required": classification != ALREADY_LOW,
        "recovery_write_required": classification != ALREADY_LOW,
        "closure_ready": classification == ALREADY_LOW,
        "live_image_required": classification is None,
    }


build_recovery_plan = recovery_plan


# ---------------------------------------------------------------------------
# Fixed CLI surface (host-only phase)
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the deliberately minimal recovery CLI.

    The source journal, partition, offset, value, payload, device node,
    transport, and timeout are not selectable through command-line controls.
    A later live owner may pass its already-bound source path internally.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--execute", action="store_true")
    return parser


def execute(args: argparse.Namespace, *, source_path: Path | None = None, live_image: bytes | None = None) -> dict[str, object]:
    """Validate the host-only portion under an explicit execution gate.

    This function intentionally performs no live action.  It returns a
    validated plan when the caller supplies a source journal and, optionally,
    an already-captured image.  Omitting the source is a hard stop rather than
    permission to guess a path or contact a device.
    """

    if getattr(args, "execute", False) is not True:
        raise ParamDebugRecoveryError("persistent recovery requires explicit --execute")
    experiment_id = getattr(args, "experiment_id", None)
    if type(experiment_id) is not str or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise ParamDebugRecoveryError("invalid experiment ID")
    if source_path is None:
        for name in ("source_path", "source_journal", "journal"):
            candidate = getattr(args, name, None)
            if candidate is not None:
                source_path = Path(candidate)
                break
    if source_path is None:
        raise ParamDebugRecoveryError(
            "host-only recovery requires an internally bound source journal"
        )
    source, _raw, _digest = _stable_source(Path(source_path))
    plan = recovery_plan(source, live_image)
    plan["experiment_id"] = experiment_id
    return plan


def collect(
    args: argparse.Namespace,
    *,
    source_path: Path | None = None,
    live_image: bytes | None = None,
) -> dict[str, object]:
    """Compatibility entry point for the host-only recovery preparation."""

    return execute(args, source_path=source_path, live_image=live_image)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # There is no live runner in this bounded host-only phase.  Keeping main
    # behind the same explicit gate makes accidental invocation fail closed.
    if getattr(args, "execute", False) is not True:
        raise ParamDebugRecoveryError("persistent recovery requires explicit --execute")
    raise ParamDebugRecoveryError(
        "live recovery runner is intentionally not part of the host-only core"
    )


if __name__ == "__main__":
    raise SystemExit(main())
