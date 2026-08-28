#!/usr/bin/env python3
"""Bounded live owner for the A90 ``param.debuglevel`` recovery boundary.

The bounded live owner validates the durable ambiguous transition journal,
binds the one operator-owned A90P1 bridge, captures the complete ``sda10``
image, and classifies that image with the pure recovery core.  A stable LOW
image (with its full hash retained as observation) is a successful zero-write
terminal.  MID and TORN images are handed to
the frozen one-shot DLOW effect coordinator; its pre-arm failures remain
zero-write, while any durable marker makes later failures ambiguous and
no-replay.

The module is import-safe: importing it does not enumerate USB, inspect a
socket, launch a process, or contact a device.  All device commands are fixed
in the imported hardened helpers; the CLI exposes only safe experiment IDs,
the explicit execution gate, and finite bounded timeout values.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
from dataclasses import asdict, is_dataclass
import inspect
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Mapping, MutableMapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import a90_param_debug_recovery as core
from tools import a90_param_debug_recovery_effect as recovery_effect
from tools.a90_acm_snapshot import Command, exchange, json_bytes
from tools.a90_autohud_arbitration import run_stophud
from tools.a90_pa28_live import revalidate_bridge_binding, validate_bridge_binding
from tools.a90_param_debug_transition import (
    _claim_effect_consumption,
    _effect_claim_key,
    _effect_claim_path,
    _effect_claim_stub,
    _write_ascii_payload,
    verify_exact_param_target,
    verify_regular_file_dd,
)
from tools.a90_param_capture import (
    PARAM_DEBUG_OFFSET,
    PARAM_DEVNAME,
    PARAM_LOGICAL_BLOCK_SIZE,
    PARAM_MAJOR,
    PARAM_MINOR,
    PARAM_PARTNAME,
    PARAM_PARTITION_BYTES,
    PARAM_READ_ONLY,
    PARAM_SECTORS,
    PARAM_START_SECTOR,
    TARGET_BOOTLOADER,
    TARGET_KERNEL,
    TARGET_MODEL,
    TARGET_RUNTIME,
    TARGET_SOC,
    PARAM_STABLE_END,
    PARAM_STABLE_LOW_SHA256,
    PARAM_STABLE_MASK,
    PARAM_STABLE_MID_SHA256,
    PARAM_STABLE_OFFSET,
    PARAM_STABLE_RANGE,
    PARAM_STABLE_SIZE,
    PARAM_VOLATILE_RANGES,
    decode_fields,
    discover_param,
    parse_cmdline as parse_param_cmdline,
    stable_param_sha256,
    validate_runtime,
)
from tools.a90_partition_capture import (
    Partition,
    binary_exchange,
    create_and_validate_node,
    device_sha256,
    parse_toybox_payload,
    remove_node,
    run_toybox,
)


# Public test/owner seam for the frozen, dependency-injected one-shot effect
# coordinator.  This runner owns only the live bindings and never changes the
# coordinator's state machine.
coordinate_dlow_effect = recovery_effect.coordinate_dlow_effect


# ---------------------------------------------------------------------------
# Fixed live bindings and durable schemas
# ---------------------------------------------------------------------------

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 54321

TARGET = {
    "model": TARGET_MODEL,
    "soc": TARGET_SOC,
    "bootloader": TARGET_BOOTLOADER,
    "runtime": TARGET_RUNTIME,
    "kernel": TARGET_KERNEL,
}

RECOVERY_JOURNAL_SCHEMA = core.RECOVERY_JOURNAL_SCHEMA
RECOVERY_PUBLIC_SCHEMA = core.RECOVERY_PUBLIC_SCHEMA
JOURNAL_SCHEMA = RECOVERY_JOURNAL_SCHEMA
PUBLIC_SCHEMA = RECOVERY_PUBLIC_SCHEMA

PASS_ALREADY_LOW = "PASS_ALREADY_LOW"
RECOVERY_WRITE_REQUIRED_NOT_EXECUTED = "RECOVERY_WRITE_REQUIRED_NOT_EXECUTED"
PRE_EFFECT_PREFLIGHT_INCOMPLETE = "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
CAPTURE_HASH_MISMATCH = "CAPTURE_HASH_MISMATCH"
CAPTURE_REFUSED = "CAPTURE_REFUSED"
CLEANUP_FAILED = "CLEANUP_FAILED"
PASS_RECOVERED_LOW = "PASS_RECOVERED_LOW"
LOW_VERIFIED_PENDING_CLEANUP = "LOW_VERIFIED_PENDING_CLEANUP"
SOURCE_CLAIM_FAILED = "SOURCE_CLAIM_FAILED"

BRIDGE_BINDING = (BRIDGE_HOST, BRIDGE_PORT)
PARAM_NODE_PATH = "/dev/sdm855_mblab_sda10"
PAYLOAD_PATH = "/tmp/sdm855_mblab_param_debug_payload"
SMOKE_PATH = "/tmp/sdm855_mblab_param_debug_dd_smoke"
FIXED_TEMP_PATHS = (PAYLOAD_PATH, SMOKE_PATH)
# The live recovery write is always the physical DLOW (MID->LOW) operation.
# ``source_summary["action"]`` remains source authorization/provenance, but
# must never select a different semantic effect-claim namespace.
CANONICAL_EFFECT_ACTION = "restore-low"
SOURCE_ACTIONS = frozenset({"apply-mid", "restore-low"})

# The private journal is mutable only through our durable atomic replacement;
# the initial intent is created with O_EXCL.  The public manifest and preimage
# are one-shot files and are always created with O_EXCL.
PRIVATE_ROOT_NAME = "evidence/private"
PUBLIC_ROOT_NAME = "evidence/manifests"
JOURNAL_SUFFIX = ".journal.json"
PREIMAGE_SUFFIX = ".preimage.bin"
PREIMAGE_BASENAME_SUFFIX = PREIMAGE_SUFFIX

SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CMDLINE_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]+\Z")
KNOWN_BARE_FLAGS = frozenset({"skip_initramfs", "rootwait", "ro"})

MAX_COMMAND_TIMEOUT = 120.0
MAX_HASH_TIMEOUT = 180.0
MAX_CAPTURE_TIMEOUT = 600.0
MAX_EFFECT_TIMEOUT = 120.0
MAX_TOTAL_TIMEOUT = 1800.0
DEFAULT_COMMAND_TIMEOUT = 45.0
DEFAULT_HASH_TIMEOUT = 90.0
DEFAULT_CAPTURE_TIMEOUT = 180.0
DEFAULT_EFFECT_TIMEOUT = 45.0
DEFAULT_TOTAL_TIMEOUT = 600.0


class LiveRecoveryError(ValueError, RuntimeError):
    """Any failure of the bounded live recovery evidence contract."""


class BridgeBindingFailure(LiveRecoveryError):
    """An exact bridge revalidation failed before a remote operation."""


class RecoveryWriteRequiredStop(LiveRecoveryError):
    """A bounded recovery stop whose caller must not replay an effect."""

    def __init__(self, message: str, result: Mapping[str, object] | None = None) -> None:
        super().__init__(message)
        self.result = dict(result or {})
        self.status = self.result.get("status", RECOVERY_WRITE_REQUIRED_NOT_EXECUTED)


class CleanupFailure(LiveRecoveryError):
    """A fixed temporary-object cleanup/absence proof was not completed."""


class CaptureHashMismatch(LiveRecoveryError):
    """The complete preimage did not match both independent device hashes."""


# Short aliases make the bounded stop discoverable to callers that use the
# terminology from the write-gate contract.
RecoveryStop = RecoveryWriteRequiredStop
BoundedStop = RecoveryWriteRequiredStop
RecoveryWriteRequired = RecoveryWriteRequiredStop


def _safe_id(value: object, label: str) -> str:
    if type(value) is not str or SAFE_ID_RE.fullmatch(value) is None:
        raise LiveRecoveryError(f"{label} must be a safe fixed experiment ID")
    return value


def _validate_timeout(value: object, label: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
        or float(value) > maximum
    ):
        raise LiveRecoveryError(
            f"{label} must be finite, positive, and <= {maximum:g}s"
        )
    return float(value)


def _arg_value(args: argparse.Namespace, name: str, default: float) -> object:
    value = getattr(args, name, default)
    return default if value is None else value


def _timeout_values(args: argparse.Namespace) -> tuple[float, float, float, float, float]:
    command_value = getattr(args, "command_timeout", None)
    if command_value is None:
        command_value = getattr(args, "timeout", DEFAULT_COMMAND_TIMEOUT)
    command_timeout = _validate_timeout(
        command_value,
        "command-timeout",
        MAX_COMMAND_TIMEOUT,
    )
    hash_timeout = _validate_timeout(
        _arg_value(args, "hash_timeout", DEFAULT_HASH_TIMEOUT),
        "hash-timeout",
        MAX_HASH_TIMEOUT,
    )
    capture_timeout = _validate_timeout(
        _arg_value(args, "capture_timeout", DEFAULT_CAPTURE_TIMEOUT),
        "capture-timeout",
        MAX_CAPTURE_TIMEOUT,
    )
    effect_timeout = _validate_timeout(
        _arg_value(args, "effect_timeout", DEFAULT_EFFECT_TIMEOUT),
        "effect-timeout",
        MAX_EFFECT_TIMEOUT,
    )
    total_timeout = _validate_timeout(
        _arg_value(args, "total_timeout", DEFAULT_TOTAL_TIMEOUT),
        "total-timeout",
        MAX_TOTAL_TIMEOUT,
    )
    return command_timeout, hash_timeout, capture_timeout, effect_timeout, total_timeout


class _Budget:
    """Finite total wall-clock budget shared by all fixed command calls."""

    def __init__(self, seconds: float) -> None:
        self.deadline = time.monotonic() + seconds

    def remaining(self, requested: float, label: str) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise LiveRecoveryError(f"{label} exceeded the bounded total timeout")
        return min(requested, remaining)


def _expected_target() -> dict[str, str]:
    return dict(TARGET)


def _target_partition_record(partition: object, start_sector: object) -> dict[str, object]:
    if is_dataclass(partition):
        values = asdict(partition)
    elif isinstance(partition, Mapping):
        values = dict(partition)
    else:
        values = {
            key: getattr(partition, key)
            for key in (
                "partname",
                "devname",
                "major",
                "minor",
                "sectors",
                "byte_size",
                "read_only",
                "logical_block_size",
            )
            if hasattr(partition, key)
        }
    values["start_sector"] = start_sector
    return values


def _exact_equal(left: object, right: object) -> bool:
    """Compare JSON-like bindings without bool/int coercion."""

    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        if set(left) != set(right):
            return False
        return all(_exact_equal(left[key], right[key]) for key in left)
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            _exact_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


# ---------------------------------------------------------------------------
# Fixed path reservation and durable local publication
# ---------------------------------------------------------------------------


def _reject_symlink_components(path: Path, label: str = "path") -> None:
    """Reject a symlink at any existing lexical component of ``path``."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    current = Path(lexical.anchor or os.sep)
    parts = lexical.parts[1:] if lexical.is_absolute() else lexical.parts
    for part in parts:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise LiveRecoveryError(f"cannot inspect {label} component {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise LiveRecoveryError(f"{label} component must not be a symlink: {current}")


def _ensure_directory(path: Path, mode: int, label: str) -> None:
    _reject_symlink_components(path, label)
    try:
        path.mkdir(parents=True, exist_ok=True, mode=mode)
        info = path.lstat()
    except OSError as exc:
        raise LiveRecoveryError(f"cannot create {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise LiveRecoveryError(f"{label} is not a regular directory: {path}")
    if label.startswith("private"):
        try:
            os.chmod(path, mode)
        except OSError as exc:
            raise LiveRecoveryError(f"cannot secure {label}: {path}") from exc


def _fixed_paths(experiment_id: str, root: Path | None = None) -> dict[str, Path]:
    exp = _safe_id(experiment_id, "experiment ID")
    base = Path(REPO_ROOT if root is None else root)
    _reject_symlink_components(base, "repository root")
    private = base / PRIVATE_ROOT_NAME
    public = base / PUBLIC_ROOT_NAME
    return {
        "private_root": private,
        "public_root": public,
        "journal": private / f"{exp}{JOURNAL_SUFFIX}",
        "manifest": public / f"{exp}.manifest.json",
        "preimage": private / f"{exp}{PREIMAGE_SUFFIX}",
    }


def _validate_fixed_output_attrs(args: argparse.Namespace) -> None:
    """Reject an injected output namespace that could create a replay silo."""

    if hasattr(args, "output_root"):
        supplied_value = getattr(args, "output_root")
        if not isinstance(supplied_value, (str, os.PathLike)):
            raise LiveRecoveryError("recovery output root is fixed to REPO_ROOT")
        supplied = Path(supplied_value).resolve()
        if supplied != Path(REPO_ROOT).resolve():
            raise LiveRecoveryError("recovery output root is fixed to REPO_ROOT")


def _source_claim_path(source_summary: Mapping[str, object]) -> Path:
    return core.source_consumption_claim_path(source_summary, root=REPO_ROOT)


def _ensure_source_unclaimed(source_summary: Mapping[str, object]) -> Path:
    """Refuse a source already consumed by any earlier recovery ID."""

    try:
        claim_path = _source_claim_path(source_summary)
        if core.source_consumption_claim_exists(source_summary, root=REPO_ROOT):
            raise LiveRecoveryError(
                "source journal has already been consumed; recovery replay is forbidden"
            )
        return claim_path
    except LiveRecoveryError:
        raise
    except BaseException as exc:
        raise LiveRecoveryError(f"source-consumption claim check failed: {exc}") from exc


def _ensure_effect_unclaimed(source_summary: Mapping[str, object]) -> Path:
    """Refuse a pre-existing semantic effect claim before bridge contact."""

    preimage_hash = source_summary.get("device_stable_sha256_before")
    if type(preimage_hash) is not str or not SHA256_RE.fullmatch(preimage_hash):
        raise LiveRecoveryError("source lacks an exact preimage hash for effect claim")
    source_action = source_summary.get("action")
    if type(source_action) is not str or source_action not in SOURCE_ACTIONS:
        raise LiveRecoveryError("source lacks an exact action for effect claim")
    try:
        partition = _fixed_partition()
        # An apply-mid source's durable preimage is LOW, while the physical
        # recovery effect is restore-low from a currently observed MID image.
        # Check both deterministic hashes before bridge contact so a regular
        # transition owner cannot race this recovery owner at MID.  TORN
        # images are checked later with their exact freshly captured hash.
        candidate_hashes = [preimage_hash]
        if source_action == "apply-mid" and core.PARAM_STABLE_MID_SHA256 != preimage_hash:
            candidate_hashes.append(core.PARAM_STABLE_MID_SHA256)
        for candidate_hash in candidate_hashes:
            claim_path = _effect_claim_path(
                CANONICAL_EFFECT_ACTION,
                candidate_hash,
                partition,
                PARAM_START_SECTOR,
                root=REPO_ROOT,
            )
            if claim_path.is_symlink() or claim_path.exists():
                raise LiveRecoveryError(
                    "semantic param effect claim already exists; recovery replay is forbidden"
                )
        return _effect_claim_path(
            CANONICAL_EFFECT_ACTION,
            preimage_hash,
            partition,
            PARAM_START_SECTOR,
            root=REPO_ROOT,
        )
    except LiveRecoveryError:
        raise
    except BaseException as exc:
        raise LiveRecoveryError(f"semantic effect claim check failed: {exc}") from exc


def _claim_source(
    source_summary: Mapping[str, object],
    recovery_experiment_id: str,
    reason: str,
) -> dict[str, object]:
    """Create the fixed source claim at one of the two terminal boundaries."""

    try:
        return core.claim_source_consumption(
            source_summary,
            recovery_experiment_id,
            root=REPO_ROOT,
            reason=reason,
        )
    except BaseException as exc:
        raise LiveRecoveryError(f"source-consumption claim failed: {exc}") from exc


def _claim_stub(
    source_summary: Mapping[str, object],
    claim_path: Path,
    recovery_experiment_id: str,
    reason: str = core.SOURCE_CLAIM_REASON_EFFECT_MARKER,
) -> dict[str, object]:
    """Describe a claim whose host write failed after its O_EXCL creation."""

    return {
        "filename": claim_path.name,
        "path": str(claim_path),
        "sha256": None,
        "size": None,
        "source_experiment_id": source_summary.get("experiment_id"),
        "source_action": source_summary.get("action"),
        "source_journal": Path(str(source_summary.get("source_path", ""))).name,
        "source_journal_sha256": source_summary.get("source_sha256"),
        "source_journal_size": source_summary.get("source_size"),
        "source_identity": source_summary.get("source_identity"),
        "source_journal_identity": source_summary.get("source_identity"),
        "source_stable_sha256_before": source_summary.get("device_stable_sha256_before"),
        "stable_mask": source_summary.get("stable_mask"),
        "source_stable_range": source_summary.get("stable_range"),
        "recovery_experiment_id": recovery_experiment_id,
        "reason": reason,
        "effect_replayed": False,
        "claim_write_failed": True,
    }


def source_journal_path(source_experiment_id: str, root: Path | None = None) -> Path:
    """Derive the only permitted source journal path for a safe source ID."""

    source_id = _safe_id(source_experiment_id, "source experiment ID")
    base = Path(REPO_ROOT if root is None else root)
    # Use the pure core's no-follow/path-under-aware naming contract.
    return core.source_journal_path(base, source_id)


derive_source_path = source_journal_path
fixed_source_journal_path = source_journal_path


def recovery_journal_path(experiment_id: str, root: Path | None = None) -> Path:
    return _fixed_paths(experiment_id, root)["journal"]


private_journal_path = recovery_journal_path


def public_manifest_path(experiment_id: str, root: Path | None = None) -> Path:
    return _fixed_paths(experiment_id, root)["manifest"]


def preimage_path(experiment_id: str, root: Path | None = None) -> Path:
    return _fixed_paths(experiment_id, root)["preimage"]


preimage_file_path = preimage_path


fixed_output_paths = _fixed_paths
derive_paths = _fixed_paths


def _reserve_paths(paths: Mapping[str, Path]) -> None:
    _ensure_directory(paths["private_root"], 0o700, "private evidence root")
    _ensure_directory(paths["public_root"], 0o755, "public manifest root")
    for key in ("journal", "manifest", "preimage"):
        path = Path(paths[key])
        _reject_symlink_components(path, f"{key} path")
        if path.exists() or path.is_symlink():
            raise LiveRecoveryError(
                f"{key} path already exists; replay/no-clobber refusal: {path}"
            )
        temporary = path.with_name(path.name + ".tmp")
        if temporary.exists() or temporary.is_symlink():
            raise LiveRecoveryError(f"{key} temporary sibling already exists: {temporary}")


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise LiveRecoveryError(f"cannot open evidence directory for fsync: {path}") from exc
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes, mode: int) -> None:
    if not isinstance(data, bytes):
        raise LiveRecoveryError("durable output data must be bytes")
    _reject_symlink_components(path, "durable output")
    if path.exists() or path.is_symlink():
        raise LiveRecoveryError(f"durable output already exists: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise LiveRecoveryError(f"cannot create durable output: {path}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise LiveRecoveryError(f"durable output made no progress: {path}")
            view = view[written:]
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
    _fsync_directory(path.parent)


def _replace_json(path: Path, value: object, mode: int = 0o600) -> bytes:
    """Atomically replace one private journal and return its exact bytes."""

    data = json_bytes(value)
    _reject_symlink_components(path, "private journal")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise LiveRecoveryError(f"private journal temporary sibling already exists: {temporary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, mode)
    except OSError as exc:
        raise LiveRecoveryError(f"cannot create private journal temporary: {temporary}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return data


def _sha256(data: bytes) -> str:
    return core.sha256(data)


def _write_initial_journal(path: Path, journal: Mapping[str, object]) -> bytes:
    """Claim the final intent path once and retain partial ownership on failure."""

    data = json_bytes(journal)
    _reject_symlink_components(path, "initial private journal")
    _ensure_directory(path.parent, 0o700, "private evidence root")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise LiveRecoveryError("initial journal write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        # A final path created by O_EXCL is the ownership signal if a host
        # crash/error occurs before the initial intent is fully durable.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    _fsync_directory(path.parent)
    return data


def _persist(path: Path, journal: MutableMapping[str, object]) -> bytes:
    return _replace_json(path, journal, 0o600)


# ---------------------------------------------------------------------------
# Bridge/source/live identity checks
# ---------------------------------------------------------------------------


def _bridge_bindings_match(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def _require_binding(binding: object, label: str) -> Mapping[str, object]:
    if not isinstance(binding, Mapping):
        raise LiveRecoveryError(f"{label} bridge binding is not an object")
    listener = binding.get("listener")
    if isinstance(listener, Mapping):
        if listener.get("host") != BRIDGE_HOST or listener.get("port") != BRIDGE_PORT:
            raise LiveRecoveryError(f"{label} bridge listener is not the fixed endpoint")
    return binding


def _fresh_binding(
    initial: Mapping[str, object],
    label: str,
    binding_events: list[str],
) -> Mapping[str, object]:
    binding_events.append(label)
    try:
        current = _require_binding(revalidate_bridge_binding(initial), label)
    except BaseException as exc:
        raise BridgeBindingFailure(
            f"{label} exact bridge binding failed: {type(exc).__name__}: {exc}"
        ) from exc
    if not _bridge_bindings_match(initial, current):
        raise BridgeBindingFailure(f"{label} exact bridge binding drifted")
    return current


def _require_frame_ok(frame: object, label: str, expected_command: str | None = None) -> None:
    begin = getattr(frame, "begin", None)
    end = getattr(frame, "end", None)
    if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
        raise LiveRecoveryError(f"{label} returned no exact A90P1 END record")
    if begin.get("seq") != end.get("seq") or begin.get("cmd") != end.get("cmd"):
        raise LiveRecoveryError(f"{label} BEGIN/END identity is not exact")
    if expected_command is not None and begin.get("cmd") != expected_command:
        raise LiveRecoveryError(
            f"{label} returned command {begin.get('cmd')!r}, expected {expected_command!r}"
        )
    raw_rc = end.get("rc")
    try:
        rc = int(raw_rc, 0) if isinstance(raw_rc, str) else int(raw_rc)
    except (TypeError, ValueError) as exc:
        raise LiveRecoveryError(f"{label} returned malformed A90P1 rc") from exc
    if isinstance(raw_rc, bool) or rc != 0 or end.get("status") != "ok":
        raise LiveRecoveryError(
            f"{label} failed: rc={raw_rc!r} status={end.get('status')!r}"
        )


def parse_cmdline(payload: bytes) -> dict[str, str]:
    """Parse every live cmdline token with the fixed A90 bare-flag grammar."""
    try:
        return parse_param_cmdline(payload)
    except BaseException as exc:
        raise LiveRecoveryError(
            f"live cmdline is not strict A90 token data: {exc}"
        ) from exc


def _supports_before_mutation(function: object) -> bool:
    candidate = getattr(function, "side_effect", None)
    if not callable(candidate):
        candidate = function
    try:
        parameters = inspect.signature(candidate).parameters.values()
    except (TypeError, ValueError):
        return True
    return any(
        parameter.name == "before_mutation"
        or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _invoke_bound(
    function: Any,
    positional: tuple[object, ...],
    binding,
    label: str,
) -> Any:
    """Invoke one helper once, injecting a fresh-binding callback when supported."""

    if _supports_before_mutation(function):
        return function(*positional, before_mutation=binding)
    # Narrow test doubles which intentionally expose no callback still receive
    # the same immediate binding gate; a TypeError from the helper is not
    # mistaken for a signature mismatch and is never retried.
    binding(label)
    return function(*positional)


def _validate_live_identity(
    source_summary: Mapping[str, object],
    budget: _Budget,
    command_timeout: float,
) -> tuple[dict[str, str], str, Partition, int, dict[str, object]]:
    version_frame = exchange(
        BRIDGE_HOST,
        BRIDGE_PORT,
        Command("version", ("version",)),
        budget.remaining(command_timeout, "version"),
    )
    _require_frame_ok(version_frame, "version", "version")
    cmdline_frame = exchange(
        BRIDGE_HOST,
        BRIDGE_PORT,
        Command("proc_cmdline", ("cat", "/proc/cmdline")),
        budget.remaining(command_timeout, "proc_cmdline"),
    )
    _require_frame_ok(cmdline_frame, "proc_cmdline", "cat")
    try:
        cmdline = parse_cmdline(cmdline_frame.payload)
    except BaseException as exc:
        raise LiveRecoveryError("live /proc/cmdline is not strict ASCII key/value data") from exc
    try:
        validate_runtime(version_frame.payload, cmdline)
    except BaseException as exc:
        raise LiveRecoveryError(f"live V2321 identity validation failed: {exc}") from exc

    relevant_keys = tuple(core.SOURCE_CMDLINE_KEYS)
    live_relevant = {key: cmdline.get(key) for key in relevant_keys}
    expected_relevant = source_summary.get("cmdline_relevant")
    if not isinstance(expected_relevant, Mapping):
        raise LiveRecoveryError("source summary lacks its validated relevant cmdline")
    expected_relevant = {key: expected_relevant.get(key) for key in relevant_keys}
    source_action = source_summary.get("action")
    if type(source_action) is not str or source_action not in SOURCE_ACTIONS:
        raise LiveRecoveryError("source action is not exact for live identity")

    # Model/bootloader and the safety invariants must remain exactly bound to
    # the source/fixed target.  The debug level is deliberately different: an
    # ambiguous transition may have happened before or after a reboot, so the
    # live boot may truthfully report either LOW or MID.  The complete param
    # capture below remains the authority for the current physical state.
    fixed_invariants = {
        "androidboot.em.model": TARGET_MODEL,
        "androidboot.bootloader": TARGET_BOOTLOADER,
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
        "androidboot.upload_offset": "9438196",
    }
    for key, fixed_value in fixed_invariants.items():
        if expected_relevant.get(key) != fixed_value:
            raise LiveRecoveryError(
                f"source relevant cmdline invariant is not exact for {key}"
            )
        if live_relevant.get(key) != fixed_value:
            raise LiveRecoveryError(f"live {key} is not the fixed value {fixed_value}")
    allowed_debug = {"0x4f4c", "0x494d"}
    source_debug = expected_relevant.get("androidboot.debug_level")
    live_debug = live_relevant.get("androidboot.debug_level")
    if source_debug not in allowed_debug:
        raise LiveRecoveryError("source debug level is not an allowed exact value")
    if live_debug not in allowed_debug:
        raise LiveRecoveryError("live debug level is not LOW or MID")

    download_frame = exchange(
        BRIDGE_HOST,
        BRIDGE_PORT,
        Command(
            "download_mode",
            ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
        ),
        budget.remaining(command_timeout, "download_mode"),
    )
    _require_frame_ok(download_frame, "download_mode", "cat")
    try:
        download_mode = download_frame.payload.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise LiveRecoveryError("live download_mode is not strict ASCII") from exc
    if download_mode != "1":
        raise LiveRecoveryError("live download_mode is not 1")

    partition, start_sector = discover_param(
        BRIDGE_HOST,
        BRIDGE_PORT,
        budget.remaining(command_timeout, "discover_param"),
    )
    if start_sector != PARAM_START_SECTOR:
        raise LiveRecoveryError(
            f"live param start sector is not the exact pinned {PARAM_START_SECTOR}"
        )
    if getattr(partition, "node_path", PARAM_NODE_PATH) != PARAM_NODE_PATH:
        raise LiveRecoveryError("live param node path is not the fixed sda10 node")
    live_partition = _target_partition_record(partition, start_sector)
    expected_partition = source_summary.get("partition")
    if not isinstance(expected_partition, Mapping) or not _exact_equal(
        live_partition, dict(expected_partition)
    ):
        raise LiveRecoveryError(
            f"live GPT/param binding differs from source: "
            f"live={live_partition!r} source={expected_partition!r}"
        )
    return cmdline, download_mode, partition, int(start_sector), live_partition


# ---------------------------------------------------------------------------
# Fixed temporary cleanup and full preimage capture
# ---------------------------------------------------------------------------


def _cleanup_temp(
    host: str,
    port: int,
    path: str,
    timeout: float,
    evidence: str,
    *,
    before_mutation=None,
) -> None:
    """Remove one fixed temporary path and prove both absence predicates."""

    if path not in FIXED_TEMP_PATHS:
        raise LiveRecoveryError(f"temporary path is not fixed: {path!r}")
    if before_mutation is not None:
        before_mutation(f"{evidence}_rm")
    output = parse_toybox_payload(
        run_toybox(host, port, evidence, ("rm", "-f", path), timeout), evidence
    )
    if output not in (b"", b"\n"):
        raise LiveRecoveryError(f"{evidence} returned unexpected rm output")
    for index, argv in enumerate(
        (("test", "!", "-e", path), ("test", "!", "-L", path)), 1
    ):
        label = f"{evidence}_absent_{index}"
        if before_mutation is not None:
            before_mutation(label)
        check = parse_toybox_payload(run_toybox(host, port, label, argv, timeout), label)
        if check not in (b"", b"\n"):
            raise LiveRecoveryError(f"{label} returned unexpected output")


def _fixed_partition() -> Partition:
    return Partition(
        partname=PARAM_PARTNAME,
        devname=PARAM_DEVNAME,
        major=PARAM_MAJOR,
        minor=PARAM_MINOR,
        sectors=PARAM_SECTORS,
        byte_size=PARAM_PARTITION_BYTES,
        read_only=PARAM_READ_ONLY,
        logical_block_size=PARAM_LOGICAL_BLOCK_SIZE,
    )


def _cleanup_all(
    partition: Partition,
    binding: Mapping[str, object],
    budget: _Budget,
    command_timeout: float,
    binding_events: list[str],
) -> list[str]:
    """Clean all fixed remote objects, retaining every failure for the journal."""

    errors: list[str] = []
    binding_failed = False

    def fresh(label: str) -> Mapping[str, object]:
        return _fresh_binding(binding, label, binding_events)

    for index, path in enumerate(FIXED_TEMP_PATHS, 1):
        label = f"cleanup_temp_{index}"
        try:
            _invoke_bound(
                _cleanup_temp,
                (
                    BRIDGE_HOST,
                    BRIDGE_PORT,
                    path,
                    budget.remaining(command_timeout, label),
                    label,
                ),
                fresh,
                label,
            )
        except BridgeBindingFailure as exc:
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            binding_failed = True
            break
        except BaseException as exc:
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            # A normal command failure may still leave the other fixed path
            # to clean.  Only the typed binding signal is fail-closed.

    if not binding_failed:
        try:
            _invoke_bound(
                remove_node,
                (
                    BRIDGE_HOST,
                    BRIDGE_PORT,
                    partition,
                    budget.remaining(command_timeout, "cleanup_param_node"),
                ),
                fresh,
                "cleanup_param_node",
            )
        except BridgeBindingFailure as exc:
            errors.append(f"cleanup_param_node: {type(exc).__name__}: {exc}")
        except BaseException as exc:
            errors.append(f"cleanup_param_node: {type(exc).__name__}: {exc}")
    return errors


def _capture_preimage(
    partition: Partition,
    preimage_path_value: Path,
    budget: _Budget,
    command_timeout: float,
    hash_timeout: float,
    capture_timeout: float,
    *,
    before_remote=None,
) -> dict[str, object]:
    """Capture exactly 10 MiB and require independent before/host/after hashes."""

    if before_remote is not None:
        before_remote("capture_before_hash")
    before_hash = device_sha256(
        BRIDGE_HOST,
        BRIDGE_PORT,
        partition,
        budget.remaining(hash_timeout, "device_sha256_before"),
        "recovery_before",
    )
    try:
        if before_remote is not None:
            before_remote("capture_binary")
        capture_result = binary_exchange(
            BRIDGE_HOST,
            BRIDGE_PORT,
            partition.node_path,
            PARAM_PARTITION_BYTES,
            budget.remaining(capture_timeout, "param_preimage_capture"),
        )
    except BridgeBindingFailure:
        raise
    except BaseException as exc:
        raise LiveRecoveryError(f"complete param preimage capture failed: {exc}") from exc
    if isinstance(capture_result, tuple) and len(capture_result) == 2:
        end_fields, image = capture_result
    else:
        end_fields, image = None, capture_result
    if type(image) is not bytes or len(image) != PARAM_PARTITION_BYTES:
        raise LiveRecoveryError(
            f"param preimage is not exactly {PARAM_PARTITION_BYTES} bytes"
        )
    host_hash = _sha256(image)
    stable_hash = stable_param_sha256(image)
    decoded_fields = decode_fields(image)
    _write_new(preimage_path_value, image, 0o600)
    if before_remote is not None:
        before_remote("capture_after_hash")
    after_hash = device_sha256(
        BRIDGE_HOST,
        BRIDGE_PORT,
        partition,
        budget.remaining(hash_timeout, "device_sha256_after"),
        "recovery_after",
    )
    hashes = {
        "device_sha256_before": before_hash,
        "host_sha256": host_hash,
        "device_sha256_after": after_hash,
    }
    if (
        not all(type(value) is str and SHA256_RE.fullmatch(value) for value in hashes.values())
        or before_hash != host_hash
        or after_hash != host_hash
    ):
        raise CaptureHashMismatch(
            "complete param preimage hash mismatch: "
            f"before={before_hash} host={host_hash} after={after_hash}"
        )
    return {
        "path": preimage_path_value.name,
        "private_filename": preimage_path_value.name,
        "size": len(image),
        "sha256": host_hash,
        "full_sha256": host_hash,
        "stable_sha256": stable_hash,
        "stable_range": {
            "start": PARAM_STABLE_OFFSET,
            "end": PARAM_STABLE_END,
            "size": PARAM_STABLE_SIZE,
            "sha256": stable_hash,
        },
        "stable_mask": {
            "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
            "stable_ranges": [list(PARAM_STABLE_RANGE)],
            "stable_size": PARAM_STABLE_SIZE,
        },
        "volatile_byte0": image[0],
        "observed_boot_cycle_volatile_byte0": image[0],
        "decoded_fields": decoded_fields,
        "device_sha256_before": before_hash,
        "device_sha256_after": after_hash,
        "device_stable_sha256_before": stable_hash,
        "device_stable_sha256_after": stable_hash,
        "a90p1_end": dict(end_fields) if isinstance(end_fields, Mapping) else end_fields,
        "image": image,
    }


def _capture_exact_effect_image(
    partition: Partition,
    budget: _Budget,
    capture_timeout: float,
    *,
    label: str,
) -> dict[str, object]:
    """Read one exact post-effect image through bounded binary_exchange."""

    try:
        capture_result = binary_exchange(
            BRIDGE_HOST,
            BRIDGE_PORT,
            partition.node_path,
            PARAM_PARTITION_BYTES,
            budget.remaining(capture_timeout, label),
        )
    except BridgeBindingFailure:
        raise
    except BaseException as exc:
        raise LiveRecoveryError(f"{label} failed: {exc}") from exc
    if isinstance(capture_result, tuple) and len(capture_result) == 2:
        end_fields, image = capture_result
    else:
        end_fields, image = None, capture_result
    if type(image) is not bytes or len(image) != PARAM_PARTITION_BYTES:
        raise LiveRecoveryError(
            f"{label} is not exactly {PARAM_PARTITION_BYTES} bytes"
        )
    full_hash = _sha256(image)
    stable_hash = stable_param_sha256(image)
    return {
        "size": len(image),
        "sha256": full_hash,
        "full_sha256": full_hash,
        "device_sha256_after": full_hash,
        "stable_sha256": stable_hash,
        "stable_range": {
            "start": PARAM_STABLE_OFFSET,
            "end": PARAM_STABLE_END,
            "size": PARAM_STABLE_SIZE,
            "sha256": stable_hash,
        },
        "stable_mask": {
            "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
            "stable_ranges": [list(PARAM_STABLE_RANGE)],
            "stable_size": PARAM_STABLE_SIZE,
        },
        "volatile_byte0": image[0],
        "observed_boot_cycle_volatile_byte0": image[0],
        "decoded_fields": decode_fields(image),
        "device_stable_sha256_after": stable_hash,
        "a90p1_end": dict(end_fields) if isinstance(end_fields, Mapping) else end_fields,
        "image": image,
    }


def _effect_marker_durable(journal: Mapping[str, object]) -> bool:
    """Return whether the frozen coordinator crossed its durable arm marker."""

    return (
        journal.get("effect_armed") is True
        and journal.get("effect_dispatched") is True
        and journal.get("effect_dispatched_count") == 1
        and journal.get("write_count") == 1
        and journal.get("partition_writes") is True
        and journal.get("effect_replayed") is False
    )


# ---------------------------------------------------------------------------
# Redacted public publication and run owner
# ---------------------------------------------------------------------------


def _public_manifest(
    journal: Mapping[str, object],
    journal_path_value: Path,
    journal_bytes: bytes,
    manifest_path_value: Path,
) -> bytes:
    preimage = journal.get("preimage")
    if not isinstance(preimage, Mapping):
        preimage_public: dict[str, object] | None = None
    else:
        fixed_preimage_filename = preimage.get("private_filename")
        if type(fixed_preimage_filename) is not str:
            fixed_preimage_filename = journal.get("private_preimage")
        preimage_public = {
            "sha256": preimage.get("sha256"),
            "full_sha256": preimage.get("full_sha256", preimage.get("sha256")),
            "stable_sha256": preimage.get("stable_sha256"),
            "stable_range": preimage.get("stable_range"),
            "stable_mask": preimage.get("stable_mask"),
            "volatile_byte0": preimage.get("volatile_byte0"),
            "observed_boot_cycle_volatile_byte0": preimage.get(
                "observed_boot_cycle_volatile_byte0", preimage.get("volatile_byte0")
            ),
            "size": preimage.get("size"),
            "private_filename": fixed_preimage_filename,
        }
    cleanup = journal.get("cleanup")
    cleanup_public = (
        {
            "proved": cleanup.get("proved"),
            "temporary_paths": list(FIXED_TEMP_PATHS),
            "param_node": PARAM_NODE_PATH,
        }
        if isinstance(cleanup, Mapping)
        else None
    )
    effect_dispatched = journal.get("effect_dispatched", False)
    effect_public = {
        "dispatched": effect_dispatched,
        "write_count": journal.get("write_count", 0),
        "partition_writes": journal.get("partition_writes", False),
        "replayed": journal.get("effect_replayed", False),
        "fixed_dlow": bool(effect_dispatched),
    }
    semantic_claim = journal.get("effect_consumption_claim")
    semantic_claim_public = None
    if isinstance(semantic_claim, Mapping):
        semantic_claim_public = {
            key: semantic_claim.get(key)
            for key in (
                "filename",
                "key",
                "sha256",
                "size",
                "action",
                "preimage_sha256",
                "preimage_full_sha256",
                "stable_preimage_sha256",
                "stable_mask",
                "partition",
                "effect_replayed",
                "claim_write_failed",
            )
        }
    claim = journal.get("source_consumption_claim")
    claim_public = None
    if isinstance(claim, Mapping):
        claim_public = {
            key: claim.get(key)
            for key in (
                "filename",
                "sha256",
                "size",
                "source_experiment_id",
                "source_journal",
                "source_journal_sha256",
                "source_journal_size",
                "source_identity",
                "source_journal_identity",
                "stable_preimage_sha256",
                "stable_mask",
                "reason",
                "effect_replayed",
                "claim_write_failed",
            )
        }
    public: dict[str, object] = {
        "schema": RECOVERY_PUBLIC_SCHEMA,
        "experiment_id": journal.get("experiment_id"),
        "source_experiment_id": journal.get("source_experiment_id"),
        "source_action": journal.get("source_action"),
        "started_utc": journal.get("started_utc"),
        "completed_utc": journal.get("completed_utc"),
        "source_journal": journal.get("source_journal"),
        "status": journal.get("status"),
        "classification": journal.get("classification"),
        "target": journal.get("target"),
        "partition": journal.get("partition"),
        "source_journal_sha256": journal.get("source_journal_sha256"),
        "source_journal_identity": journal.get("source_journal_identity"),
        "source_cmdline_relevant": journal.get("source_cmdline_relevant"),
        "cmdline_relevant": journal.get("cmdline_relevant"),
        "live_cmdline_relevant": journal.get("live_cmdline_relevant"),
        "source_debug_level": journal.get("source_debug_level"),
        "live_debug_level": journal.get("live_debug_level"),
        "source_consumption_claim": claim_public,
        "source_consumption_claim_path": journal.get(
            "source_consumption_claim_path"
        ),
        "effect_consumption_claim": semantic_claim_public,
        "effect_consumption_claim_path": journal.get("effect_consumption_claim_path"),
        "preimage": preimage_public,
        "device_sha256_before": journal.get("device_sha256_before"),
        "device_sha256_after": journal.get("device_sha256_after"),
        "device_stable_sha256_before": journal.get("device_stable_sha256_before"),
        "device_stable_sha256_after": journal.get("device_stable_sha256_after"),
        "stable_mask": journal.get("stable_mask"),
        "volatile_byte0_before": journal.get("volatile_byte0_before"),
        "volatile_byte0_after": journal.get("volatile_byte0_after"),
        "observed_boot_cycle_volatile_byte0_before": journal.get(
            "volatile_byte0_before"
        ),
        "observed_boot_cycle_volatile_byte0_after": journal.get(
            "volatile_byte0_after"
        ),
        "write_count": journal.get("write_count", 0),
        "effect_dispatched": journal.get("effect_dispatched", False),
        "effect_dispatched_count": journal.get("effect_dispatched_count", 0),
        "effect_replayed": journal.get("effect_replayed", False),
        "partition_writes": journal.get("partition_writes", False),
        "reconcile_required": journal.get("reconcile_required", True),
        "reconciliation_required": journal.get("reconcile_required", True),
        "current_state": journal.get("current_state"),
        "effect": effect_public,
        "cleanup": cleanup_public,
        "private_journal": {
            "filename": journal_path_value.name,
            "sha256": _sha256(journal_bytes),
            "size": len(journal_bytes),
        },
        "journal": journal_path_value.name,
        "preimage_filename": preimage_public.get("private_filename") if preimage_public else None,
        # Repeated scalar aliases keep the binding obvious to simple tooling;
        # all are derived from the exact final private bytes above.
        "private_journal_sha256": _sha256(journal_bytes),
        "journal_sha256": _sha256(journal_bytes),
        "private_journal_size": len(journal_bytes),
        "private_journal_filename": journal_path_value.name,
        "journal_path": journal_path_value.name,
        "preimage_sha256": preimage_public.get("sha256") if preimage_public else None,
        "preimage_hash": preimage_public.get("sha256") if preimage_public else None,
        "preimage_size": preimage_public.get("size") if preimage_public else None,
        "redaction": {
            "raw_cmdline": "omitted",
            "serial_identity": "omitted",
            "raw_transcript": "omitted",
            "preimage_bytes": "omitted",
            "payload_base64": "omitted",
            "partition_effect_argv": "omitted; fixed DLOW effect is schema-bound",
        },
        "manifest_filename": manifest_path_value.name,
    }
    return json_bytes(public)


def _publish_final(
    journal_path_value: Path,
    manifest_path_value: Path,
    journal: MutableMapping[str, object],
) -> tuple[bytes, bytes]:
    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    journal["completed_utc"] = completed
    final_journal = _persist(journal_path_value, journal)
    public_bytes = _public_manifest(
        journal, journal_path_value, final_journal, manifest_path_value
    )
    _write_new(manifest_path_value, public_bytes, 0o644)
    return final_journal, public_bytes


def _incident_manifest(
    journal: MutableMapping[str, object],
    journal_path_value: Path,
    manifest_path_value: Path,
    error: BaseException,
) -> None:
    """Publish a redacted incident when preflight/capture/effect stops."""

    journal["error"] = f"{type(error).__name__}: {error}"
    journal["completed_utc"] = dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0
    ).isoformat()
    final_journal = _persist(journal_path_value, journal)
    try:
        _write_new(
            manifest_path_value,
            _public_manifest(
                journal, journal_path_value, final_journal, manifest_path_value
            ),
            0o644,
        )
    except BaseException:
        # Preserve the private journal as the durable incident if publication
        # itself is blocked by an output fault; the original failure remains
        # the one reported by the caller.
        pass


def _fresh_journal(
    experiment_id: str,
    source_experiment_id: str,
    source_path_value: Path,
    source_summary: Mapping[str, object],
    paths: Mapping[str, Path],
    started: str,
    source_claim_path_value: Path | None = None,
    effect_claim_path_value: Path | None = None,
) -> dict[str, object]:
    return {
        "schema": RECOVERY_JOURNAL_SCHEMA,
        "experiment_id": experiment_id,
        "source_experiment_id": source_experiment_id,
        "source_action": source_summary.get("action"),
        "source_journal": source_path_value.name,
        "source_journal_sha256": source_summary.get("source_sha256"),
        "source_journal_size": source_summary.get("source_size"),
        "source_journal_identity": source_summary.get("source_identity"),
        "source_cmdline_relevant": dict(source_summary.get("cmdline_relevant", {})),
        "live_cmdline_relevant": None,
        "source_debug_level": source_summary.get("cmdline_relevant", {}).get(
            "androidboot.debug_level"
        )
        if isinstance(source_summary.get("cmdline_relevant"), Mapping)
        else None,
        "live_debug_level": None,
        "source_consumption_claim": None,
        "effect_consumption_claim": None,
        "started_utc": started,
        "status": "RECOVERY_INTENT_DURABLE",
        "classification": None,
        "target": None,
        "partition": None,
        "preimage": None,
        "device_sha256_before": None,
        "device_sha256_after": None,
        "device_stable_sha256_before": None,
        "device_stable_sha256_after": None,
        "stable_range_before": None,
        "stable_range_after": None,
        "volatile_byte0_before": None,
        "volatile_byte0_after": None,
        "effect_armed": False,
        "effect_dispatched": False,
        "effect_dispatched_count": 0,
        "write_count": 0,
        "partition_writes": False,
        "effect_replayed": False,
        "reconcile_required": True,
        "reconciliation_required": True,
        "recovery_write_required": True,
        "cleanup": {"proved": False, "errors": []},
        "private_preimage": paths["preimage"].name,
        "public_manifest": paths["manifest"].name,
        "source_consumption_claim_path": (
            source_claim_path_value.name if source_claim_path_value is not None else None
        ),
        "effect_consumption_claim_path": (
            effect_claim_path_value.name if effect_claim_path_value is not None else None
        ),
    }


def execute(args: argparse.Namespace) -> tuple[Path, Path]:
    """Execute the bounded live runner and return journal/manifest paths.

    MID/TORN classification runs through the frozen one-shot effect
    coordinator.  Pre-arm failures retain zero-write cleanup semantics;
    failures after a durable effect marker are published as ambiguous and
    skip all later device commands.  A successful effect reaches
    ``PASS_RECOVERED_LOW`` only after cleanup/absence proof.
    """

    if getattr(args, "execute", False) is not True:
        raise LiveRecoveryError("persistent recovery requires explicit --execute")
    _validate_fixed_output_attrs(args)
    experiment_id = _safe_id(getattr(args, "experiment_id", None), "experiment ID")
    source_experiment_id = _safe_id(
        getattr(args, "source_experiment_id", None), "source experiment ID"
    )
    # The parser does not expose endpoint controls.  If an embedding caller
    # supplies legacy-looking attributes anyway, reject non-fixed values
    # rather than silently allowing them to influence a run.
    if hasattr(args, "host") and getattr(args, "host") != BRIDGE_HOST:
        raise LiveRecoveryError("recovery only accepts the fixed 127.0.0.1 bridge")
    if hasattr(args, "port") and getattr(args, "port") != BRIDGE_PORT:
        raise LiveRecoveryError("recovery only accepts the fixed 54321 bridge port")
    (
        command_timeout,
        hash_timeout,
        capture_timeout,
        effect_timeout,
        total_timeout,
    ) = _timeout_values(args)

    source_path_value = source_journal_path(source_experiment_id)
    try:
        source_summary = core.validate_source_path(source_path_value, root=REPO_ROOT)
    except BaseException as exc:
        raise LiveRecoveryError(f"source journal validation failed: {exc}") from exc
    if source_summary.get("experiment_id") != source_experiment_id:
        raise LiveRecoveryError(
            "source journal experiment ID does not match its fixed path"
        )
    # Refuse a consumed source before reserving this run's output, binding the
    # bridge, or issuing stophud/capture commands.  The source ID is the claim
    # namespace key; a fresh recovery experiment ID cannot bypass it.
    source_claim_path = _ensure_source_unclaimed(source_summary)
    effect_claim_path = _ensure_effect_unclaimed(source_summary)
    paths = _fixed_paths(experiment_id)
    _reserve_paths(paths)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    journal = _fresh_journal(
        experiment_id,
        source_experiment_id,
        source_path_value,
        source_summary,
        paths,
        started,
        source_claim_path,
        effect_claim_path,
    )
    # This is deliberately before bridge binding and therefore before any
    # possible device command.  It is the durable no-replay intent boundary.
    _write_initial_journal(paths["journal"], journal)

    budget = _Budget(total_timeout)
    bridge_binding: Mapping[str, object] | None = None
    binding_events: list[str] = []
    partition: Partition = _fixed_partition()
    node_attempted = False
    cleanup_allowed = False
    effect_marker_durable = False
    effect_succeeded = False
    effect_claim: dict[str, object] | None = None
    semantic_effect_claim: dict[str, object] | None = None
    effect_claim_boundary = False

    try:
        try:
            bridge_binding = _require_binding(validate_bridge_binding(), "initial")
        except BaseException:
            journal["status"] = PRE_EFFECT_PREFLIGHT_INCOMPLETE
            raise
        journal["bridge_binding"] = dict(bridge_binding)
        _persist(paths["journal"], journal)

        # stophud is intentionally the first device action.  The initial
        # bridge validation above is host-only ownership/binding evidence;
        # revalidate the same binding immediately before this stateful call.
        _fresh_binding(bridge_binding, "pre_stophud", binding_events)
        stophud_records: list[dict[str, object]] = []

        def stophud_exchange(host, port, command, timeout, **kwargs):
            # Rebind immediately before every bounded stophud retry.  A busy
            # refusal may be retried, but a changed bridge cannot reach a
            # second attempt or any later substantive command.
            _fresh_binding(bridge_binding, "pre_stophud_attempt", binding_events)
            return exchange(host, port, command, timeout, **kwargs)

        def persist_stophud(attempts: list[dict[str, object]]) -> None:
            journal["stophud_attempts"] = attempts
            _persist(paths["journal"], journal)

        stophud = run_stophud(
            BRIDGE_HOST,
            BRIDGE_PORT,
            budget.remaining(command_timeout, "stophud"),
            stophud_exchange,
            frame_records=stophud_records,
            persist=persist_stophud,
        )
        journal["stophud"] = stophud
        journal["stophud_frames"] = stophud_records
        _persist(paths["journal"], journal)
        # A stophud exchange is stateful; bind the same bridge again directly
        # before the first live identity read that follows it.
        _fresh_binding(bridge_binding, "pre_live_identity", binding_events)

        cmdline, download_mode, partition, start_sector, live_partition = _validate_live_identity(
            source_summary, budget, command_timeout
        )
        journal["target"] = _expected_target()
        journal["partition"] = live_partition
        journal["cmdline_relevant"] = {
            key: cmdline.get(key) for key in core.SOURCE_CMDLINE_KEYS
        }
        journal["live_cmdline_relevant"] = dict(journal["cmdline_relevant"])
        journal["source_cmdline_relevant"] = dict(source_summary["cmdline_relevant"])
        journal["source_debug_level"] = source_summary["cmdline_relevant"].get(
            "androidboot.debug_level"
        )
        journal["live_debug_level"] = cmdline.get("androidboot.debug_level")
        journal["download_mode"] = download_mode
        journal["target_verified"] = True
        journal["status"] = "PREFLIGHT"
        _persist(paths["journal"], journal)

        # Every helper mutation receives a fresh bridge callback.  Mark the
        # node as possibly touched before invocation so a helper that fails
        # after mknod still enters the cleanup path.
        node_attempted = True

        def fresh(label: str) -> Mapping[str, object]:
            if bridge_binding is None:
                raise LiveRecoveryError(f"{label} lacks initial bridge binding")
            return _fresh_binding(bridge_binding, label, binding_events)

        _invoke_bound(
            create_and_validate_node,
            (
                BRIDGE_HOST,
                BRIDGE_PORT,
                partition,
                budget.remaining(command_timeout, "create_param_node"),
            ),
            fresh,
            "create_param_node",
        )

        capture = _capture_preimage(
            partition,
            paths["preimage"],
            budget,
            command_timeout,
            hash_timeout,
            capture_timeout,
            before_remote=fresh,
        )
        image = capture.pop("image")
        if not isinstance(image, bytes):
            raise LiveRecoveryError("captured preimage bytes are unavailable")
        journal["preimage"] = capture
        journal["device_sha256_before"] = capture["device_sha256_before"]
        journal["device_sha256_after"] = capture["device_sha256_after"]
        journal["device_stable_sha256_before"] = capture["stable_sha256"]
        journal["device_stable_sha256_after"] = capture["stable_sha256"]
        journal["stable_range_before"] = capture["stable_range"]
        journal["stable_range_after"] = capture["stable_range"]
        journal["volatile_byte0_before"] = capture["volatile_byte0"]
        journal["volatile_byte0_after"] = capture["volatile_byte0"]
        journal["decoded_fields_before"] = capture["decoded_fields"]
        journal["classification"] = core.classify_live_image(image)
        classification = journal["classification"]
        if classification not in {
            core.ALREADY_LOW,
            core.RECOVERABLE_MID,
            core.RECOVERABLE_TORN,
        }:
            raise LiveRecoveryError(f"pure core returned unknown classification: {classification!r}")
        journal["status"] = (
            PASS_ALREADY_LOW
            if classification == core.ALREADY_LOW
            else RECOVERY_WRITE_REQUIRED_NOT_EXECUTED
        )
        journal["recovery_write_required"] = classification != core.ALREADY_LOW
        journal["reconcile_required"] = classification != core.ALREADY_LOW
        journal["reconciliation_required"] = classification != core.ALREADY_LOW
        journal["binding_checks"] = list(binding_events)
        _persist(paths["journal"], journal)

        if classification in {core.RECOVERABLE_MID, core.RECOVERABLE_TORN}:
            # The frozen coordinator owns the one-shot effect marker and
            # dispatch state.  These closures only bind fixed production
            # helpers; no caller-controlled path, partition, or argv reaches
            # the coordinator.
            def effect_persist(effect_journal: MutableMapping[str, object]) -> None:
                nonlocal effect_claim, semantic_effect_claim, effect_claim_boundary
                # The coordinator invokes this callback for the marker after
                # staging/smoke and immediately before its sole dispatch.  A
                # source claim is atomically created in that same host-side
                # boundary; if either claim or journal persistence fails, the
                # marker is not durable and the effect is never dispatched.
                if (
                    effect_journal.get("status")
                    == recovery_effect.EFFECT_DISPATCH_STARTED
                    and not isinstance(
                        effect_journal.get("effect_consumption_claim"), Mapping
                    )
                ):
                    # Serialize the exact observed preimage/geometry, not
                    # mutable journal JSON.  The source action is retained as
                    # provenance above, while the physical DLOW effect always
                    # uses one canonical key, so two source IDs cannot
                    # concurrently dispatch the same semantic DLOW effect.
                    preimage_hash = journal.get("device_stable_sha256_before")
                    if type(preimage_hash) is not str or not SHA256_RE.fullmatch(
                        preimage_hash
                    ):
                        raise LiveRecoveryError(
                            "effect claim lacks an exact captured preimage hash"
                        )
                    source_action = source_summary.get("action")
                    if type(source_action) is not str or source_action not in SOURCE_ACTIONS:
                        raise LiveRecoveryError("effect claim lacks an exact source action")
                    effect_claim_path = _effect_claim_path(
                        CANONICAL_EFFECT_ACTION,
                        preimage_hash,
                        partition,
                        start_sector,
                        root=REPO_ROOT,
                    )
                    journal["effect_consumption_claim_path"] = effect_claim_path.name
                    try:
                        semantic_effect_claim = _claim_effect_consumption(
                            CANONICAL_EFFECT_ACTION,
                            preimage_hash,
                            partition,
                            start_sector,
                            experiment_id,
                            root=REPO_ROOT,
                            full_preimage_hash=journal.get("device_sha256_before"),
                        )
                    except BaseException:
                        # An O_EXCL-created partial claim is itself a
                        # no-replay boundary. Preserve a receipt and let the
                        # outer owner skip cleanup on this losing run.
                        effect_claim_boundary = (
                            effect_claim_path.exists() or effect_claim_path.is_symlink()
                        )
                        if effect_claim_boundary:
                            semantic_effect_claim = _effect_claim_stub(
                                effect_claim_path,
                                _effect_claim_key(
                                    CANONICAL_EFFECT_ACTION,
                                    preimage_hash,
                                    partition,
                                    start_sector,
                                ),
                                CANONICAL_EFFECT_ACTION,
                                preimage_hash,
                                partition,
                                start_sector,
                                experiment_id,
                            )
                            effect_journal["effect_consumption_claim"] = (
                                semantic_effect_claim
                            )
                        raise
                    effect_claim_boundary = True
                    if isinstance(semantic_effect_claim, Mapping):
                        semantic_effect_claim = dict(semantic_effect_claim)
                        semantic_effect_claim.update(
                            {
                                "preimage_full_sha256": journal.get("device_sha256_before"),
                                "stable_preimage_sha256": preimage_hash,
                                "stable_mask": {
                                    "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
                                    "stable_ranges": [list(PARAM_STABLE_RANGE)],
                                    "stable_size": PARAM_STABLE_SIZE,
                                },
                            }
                        )
                    effect_journal["effect_consumption_claim"] = semantic_effect_claim
                if (
                    effect_journal.get("status")
                    == recovery_effect.EFFECT_DISPATCH_STARTED
                    and not isinstance(
                        effect_journal.get("source_consumption_claim"), Mapping
                    )
                ):
                    try:
                        effect_claim = _claim_source(
                            source_summary,
                            experiment_id,
                            core.SOURCE_CLAIM_REASON_EFFECT_MARKER,
                        )
                    except BaseException:
                        # An O_EXCL claim can exist as a partial file even if
                        # its write/fsync raised.  Preserve that fact in the
                        # private/public receipt; the source remains consumed.
                        try:
                            claim_exists = core.source_consumption_claim_exists(
                                source_summary, root=REPO_ROOT
                            )
                        except BaseException:
                            claim_exists = True
                        if claim_exists:
                            effect_claim = _claim_stub(
                                source_summary,
                                source_claim_path,
                                experiment_id,
                            )
                            effect_journal["source_consumption_claim"] = effect_claim
                        raise
                    effect_journal["source_consumption_claim"] = effect_claim
                _persist(paths["journal"], effect_journal)

            def effect_fresh(label: str = "effect_fresh") -> Mapping[str, object]:
                if bridge_binding is None:
                    raise LiveRecoveryError(f"{label} lacks initial bridge binding")
                return _fresh_binding(bridge_binding, label, binding_events)

            def stage_fixed_dlow() -> dict[str, object]:
                return _invoke_bound(
                    _write_ascii_payload,
                    (
                        BRIDGE_HOST,
                        BRIDGE_PORT,
                        PAYLOAD_PATH,
                        core.DLOW_PAYLOAD,
                        budget.remaining(command_timeout, "effect_stage_dlow"),
                    ),
                    effect_fresh,
                    "effect_stage_dlow",
                )

            def verify_dd_smoke() -> dict[str, object]:
                return _invoke_bound(
                    verify_regular_file_dd,
                    (
                        BRIDGE_HOST,
                        BRIDGE_PORT,
                        PAYLOAD_PATH,
                        core.DLOW_PAYLOAD,
                        budget.remaining(command_timeout, "effect_dd_smoke"),
                    ),
                    effect_fresh,
                    "effect_dd_smoke",
                )

            def dispatch_fixed_effect() -> object:
                # The coordinator has already durably persisted its marker.
                # Re-read node rdev/geometry and the staged bytes/hash/size
                # after that marker, then bind once more directly adjacent to
                # the sole partition write.  No host fsync or unrelated
                # command occurs between this final bind and exchange().
                effect_fresh("effect_post_marker_target")
                verification = verify_exact_param_target(
                    BRIDGE_HOST,
                    BRIDGE_PORT,
                    partition,
                    start_sector,
                    PAYLOAD_PATH,
                    core.DLOW_PAYLOAD,
                    budget.remaining(command_timeout, "effect_target_final"),
                    expected_record=journal.get("payload")
                    if isinstance(journal.get("payload"), Mapping)
                    else None,
                    evidence_prefix="post_marker_target",
                )
                journal["post_marker_target_verification"] = verification
                effect_fresh("effect_dispatch_final")
                return exchange(
                    BRIDGE_HOST,
                    BRIDGE_PORT,
                    Command("param_debug_recovery", core.FIXED_EFFECT_ARGV),
                    budget.remaining(effect_timeout, "effect_dispatch"),
                    allow_error=True,
                )

            def capture_device_image() -> dict[str, object]:
                # Rebind directly adjacent to the bounded exact 10 MiB
                # post-effect exchange.  No digest-only shortcut can authorize
                # recovery: the returned bytes, stable mask, debug fields, and
                # full observation are validated by the effect coordinator.
                effect_fresh("effect_post_capture")
                return _capture_exact_effect_image(
                    partition,
                    budget,
                    capture_timeout,
                    label="effect_post_capture",
                )

            try:
                effect_result = coordinate_dlow_effect(
                    str(classification),
                    journal,
                    effect_persist,
                    effect_fresh,
                    stage_fixed_dlow,
                    verify_dd_smoke,
                    dispatch_fixed_effect,
                    capture_device_image,
                    capture_device_image=capture_device_image,
                )
                effect_marker_durable = _effect_marker_durable(journal)
                if (
                    not isinstance(effect_result, Mapping)
                    or effect_result.get("status")
                    != recovery_effect.PASS_EFFECT_LOW_VERIFIED
                    or effect_result.get("device_stable_sha256_after")
                    != core.PARAM_STABLE_LOW_SHA256
                    or not effect_marker_durable
                ):
                    raise LiveRecoveryError(
                        "frozen recovery effect did not return its exact PASS/stable-LOW result"
                    )
                effect_succeeded = True
                journal["status"] = LOW_VERIFIED_PENDING_CLEANUP
                journal["current_state"] = "LOW"
                journal["recovery_write_required"] = False
                journal["reconcile_required"] = False
                journal["reconciliation_required"] = False
                journal["cleanup_deferred"] = False
                _persist(paths["journal"], journal)
                cleanup_allowed = True
            except BaseException:
                effect_marker_durable = _effect_marker_durable(journal)
                # The source claim is created just before the marker.  If
                # persistence then fails after a host replace/fsync boundary,
                # the in-memory coordinator snapshot may no longer show the
                # marker even though the claim (or a partial claim) is
                # durable.  Treat that claim as a conservative no-replay
                # boundary and skip all remote cleanup.
                try:
                    effect_marker_durable = effect_marker_durable or core.source_consumption_claim_exists(
                        source_summary, root=REPO_ROOT
                    )
                except BaseException:
                    effect_marker_durable = True
                if effect_marker_durable:
                    if semantic_effect_claim is not None and not isinstance(
                        journal.get("effect_consumption_claim"), Mapping
                    ):
                        journal["effect_consumption_claim"] = semantic_effect_claim
                    if effect_claim is not None and not isinstance(
                        journal.get("source_consumption_claim"), Mapping
                    ):
                        journal["source_consumption_claim"] = effect_claim
                    journal.update(
                        {
                            "effect_armed": True,
                            "effect_dispatched": True,
                            "effect_dispatched_count": 1,
                            "write_count": 1,
                            "partition_writes": True,
                            "effect_replayed": False,
                        }
                    )
                    # Once the coordinator's marker is durable, its one write
                    # attempt is a no-replay boundary.  The outer failure
                    # path preserves all effect fields and skips cleanup.
                    journal["status"] = recovery_effect.AMBIGUOUS_STATUS
                    journal["current_state"] = "UNKNOWN"
                    journal["cleanup_deferred"] = True
                    journal["reconcile_required"] = True
                    journal["reconciliation_required"] = True
                    cleanup_allowed = False
                elif effect_claim_boundary:
                    if semantic_effect_claim is not None and not isinstance(
                        journal.get("effect_consumption_claim"), Mapping
                    ):
                        journal["effect_consumption_claim"] = semantic_effect_claim
                    # A semantic claim exists but the durable effect marker
                    # did not.  This owner must not clean shared objects or
                    # retry; retain zero device-write accounting while the
                    # claim keeps all competing owners out.
                    journal.update(
                        {
                            "effect_armed": False,
                            "effect_dispatched": False,
                            "effect_dispatched_count": 0,
                            "write_count": 0,
                            "partition_writes": False,
                            "effect_replayed": False,
                            "status": "PRE_EFFECT_EFFECT_CLAIM_UNAVAILABLE",
                            "cleanup_deferred": True,
                            "reconcile_required": True,
                            "reconciliation_required": True,
                        }
                    )
                    cleanup_allowed = False
                else:
                    # Pre-arm failures retain the old zero-write invariant;
                    # fixed temp/node cleanup remains permitted.
                    cleanup_allowed = True
                raise
        else:
            cleanup_allowed = True

    except RecoveryWriteRequiredStop:
        raise
    except BaseException as exc:
        # The private intent remains durable.  Once the frozen coordinator has
        # crossed its marker, preserve its write-count/ambiguity state and
        # forbid every later device command, including cleanup.  Before that
        # marker, retain the zero-write invariant and permit fixed cleanup.
        effect_marker_durable = effect_marker_durable or _effect_marker_durable(journal)
        try:
            effect_marker_durable = effect_marker_durable or core.source_consumption_claim_exists(
                source_summary, root=REPO_ROOT
            )
        except BaseException:
            effect_marker_durable = True
        if effect_marker_durable:
            if semantic_effect_claim is not None and not isinstance(
                journal.get("effect_consumption_claim"), Mapping
            ):
                journal["effect_consumption_claim"] = semantic_effect_claim
            if effect_claim is not None and not isinstance(
                journal.get("source_consumption_claim"), Mapping
            ):
                journal["source_consumption_claim"] = effect_claim
            journal.update(
                {
                    "effect_armed": True,
                    "effect_dispatched": True,
                    "effect_dispatched_count": 1,
                    "write_count": 1,
                    "partition_writes": True,
                    "effect_replayed": False,
                }
            )
            journal["reconcile_required"] = True
            journal["reconciliation_required"] = True
            journal["cleanup_deferred"] = True
            cleanup_allowed = False
        elif effect_claim_boundary:
            if semantic_effect_claim is not None and not isinstance(
                journal.get("effect_consumption_claim"), Mapping
            ):
                journal["effect_consumption_claim"] = semantic_effect_claim
            journal.update(
                {
                    "effect_armed": False,
                    "effect_dispatched": False,
                    "effect_dispatched_count": 0,
                    "write_count": 0,
                    "partition_writes": False,
                    "effect_replayed": False,
                    "status": "PRE_EFFECT_EFFECT_CLAIM_UNAVAILABLE",
                    "cleanup_deferred": True,
                    "reconcile_required": True,
                    "reconciliation_required": True,
                }
            )
            cleanup_allowed = False
        else:
            journal["effect_armed"] = False
            journal["effect_dispatched"] = False
            journal["effect_dispatched_count"] = 0
            journal["write_count"] = 0
            journal["partition_writes"] = False
            if journal.get("status") in {
                "RECOVERY_INTENT_DURABLE",
                RECOVERY_WRITE_REQUIRED_NOT_EXECUTED,
            }:
                journal["status"] = PRE_EFFECT_PREFLIGHT_INCOMPLETE
            if journal.get("status") == "PREFLIGHT":
                journal["status"] = PRE_EFFECT_PREFLIGHT_INCOMPLETE
            if isinstance(exc, CaptureHashMismatch):
                journal["status"] = CAPTURE_HASH_MISMATCH
            elif isinstance(exc, core.ParamDebugRecoveryError):
                journal["status"] = CAPTURE_REFUSED
            if bridge_binding is not None and node_attempted:
                cleanup_allowed = True
        error = exc
    else:
        error = None

    # Cleanup is itself a device filesystem mutation and therefore is gated by
    # a fresh exact binding on every helper operation.  No payload or dd
    # staging occurs in this runner; these checks only remove stale fixed
    # temporary objects and prove both -e and -L absence.
    cleanup_errors: list[str] = []
    if cleanup_allowed and bridge_binding is not None:
        try:
            cleanup_errors = _cleanup_all(
                partition,
                bridge_binding,
                budget,
                command_timeout,
                binding_events,
            )
        except BaseException as exc:
            cleanup_errors = [
                f"cleanup owner: {type(exc).__name__}: {exc}"
            ]
    if cleanup_allowed:
        journal["cleanup"] = {
            "proved": not cleanup_errors,
            "errors": cleanup_errors,
            "temporary_paths": list(FIXED_TEMP_PATHS),
            "param_node": PARAM_NODE_PATH,
            "absence_proved": not cleanup_errors,
        }
    else:
        # In particular, an ambiguous durable effect must retain a truthful
        # cleanup-deferred record: no cleanup command was issued afterward.
        retained_cleanup = journal.get("cleanup")
        if not isinstance(retained_cleanup, MutableMapping):
            retained_cleanup = {}
        retained_cleanup["proved"] = False
        retained_cleanup["absence_proved"] = False
        retained_cleanup.setdefault("errors", [])
        retained_cleanup["temporary_paths"] = list(FIXED_TEMP_PATHS)
        retained_cleanup["param_node"] = PARAM_NODE_PATH
        retained_cleanup["skipped"] = True
        journal["cleanup"] = retained_cleanup
    journal["binding_checks"] = list(binding_events)

    if error is not None:
        if cleanup_errors:
            journal["cleanup_error"] = "; ".join(cleanup_errors)
        try:
            _incident_manifest(journal, paths["journal"], paths["manifest"], error)
        except BaseException:
            # The original failure is more useful to callers than publication
            # of a secondary incident, while the journal remains durable.
            pass
        raise error

    classification = journal.get("classification")
    if classification == core.ALREADY_LOW:
        if cleanup_errors:
            journal["status"] = CLEANUP_FAILED
            journal["reconcile_required"] = True
            journal["reconciliation_required"] = True
            error = CleanupFailure("fixed temporary cleanup was not proved: " + "; ".join(cleanup_errors))
            try:
                _incident_manifest(journal, paths["journal"], paths["manifest"], error)
            except BaseException:
                pass
            raise error
        try:
            # A zero-write terminal close consumes the source only after the
            # exact LOW image and all fixed cleanup absence proofs are done.
            # The O_EXCL claim is independent of this recovery ID's journal,
            # so a later ID cannot replay the same source.
            journal["source_consumption_claim"] = _claim_source(
                source_summary,
                experiment_id,
                core.SOURCE_CLAIM_REASON_ALREADY_LOW,
            )
        except BaseException as exc:
            try:
                if core.source_consumption_claim_exists(source_summary, root=REPO_ROOT):
                    journal["source_consumption_claim"] = _claim_stub(
                        source_summary,
                        source_claim_path,
                        experiment_id,
                        core.SOURCE_CLAIM_REASON_ALREADY_LOW,
                    )
            except BaseException:
                pass
            journal["status"] = SOURCE_CLAIM_FAILED
            journal["reconcile_required"] = True
            journal["reconciliation_required"] = True
            try:
                _incident_manifest(journal, paths["journal"], paths["manifest"], exc)
            except BaseException:
                pass
            raise
        _publish_final(paths["journal"], paths["manifest"], journal)
        return paths["journal"], paths["manifest"]

    if effect_succeeded:
        if cleanup_errors:
            # The effect marker is durable.  Do not issue any additional
            # device command after a cleanup failure; preserve no-replay
            # fields and publish an ambiguous incident.
            journal["status"] = recovery_effect.AMBIGUOUS_STATUS
            journal["current_state"] = "UNKNOWN"
            journal["cleanup_deferred"] = True
            journal["reconcile_required"] = True
            journal["reconciliation_required"] = True
            journal["cleanup_error"] = "; ".join(cleanup_errors)
            error = CleanupFailure(
                "post-effect cleanup was not proved: " + "; ".join(cleanup_errors)
            )
            try:
                _incident_manifest(journal, paths["journal"], paths["manifest"], error)
            except BaseException:
                pass
            raise error
        journal["status"] = PASS_RECOVERED_LOW
        journal["current_state"] = "LOW"
        journal["cleanup_deferred"] = False
        journal["reconcile_required"] = False
        journal["reconciliation_required"] = False
        _publish_final(paths["journal"], paths["manifest"], journal)
        return paths["journal"], paths["manifest"]

    if classification in {core.RECOVERABLE_MID, core.RECOVERABLE_TORN}:
        # A MID/TORN run reaches this point only after the coordinator proved
        # its PASS/full-LOW result and cleanup was allowed.  Keep this guard
        # fail-closed if a future coordinator shape changes unexpectedly.
        raise LiveRecoveryError(
            "recoverable classification returned without a successful effect coordinator"
        )

    raise LiveRecoveryError(f"run ended without a bounded classification: {classification!r}")


run = execute
collect = execute


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--source-experiment-id", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--command-timeout",
        "--timeout",
        type=float,
        dest="command_timeout",
        default=DEFAULT_COMMAND_TIMEOUT,
        help="bounded timeout per fixed control command",
    )
    parser.add_argument(
        "--hash-timeout",
        type=float,
        default=DEFAULT_HASH_TIMEOUT,
        help="bounded timeout per fixed device hash command",
    )
    parser.add_argument(
        "--capture-timeout",
        type=float,
        default=DEFAULT_CAPTURE_TIMEOUT,
        help="bounded timeout for the exact 10 MiB capture",
    )
    parser.add_argument(
        "--effect-timeout",
        type=float,
        default=DEFAULT_EFFECT_TIMEOUT,
        help="bounded timeout for the single fixed DLOW effect command",
    )
    parser.add_argument(
        "--total-timeout",
        type=float,
        default=DEFAULT_TOTAL_TIMEOUT,
        help="bounded total live-run timeout",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        journal, manifest = execute(args)
    except RecoveryWriteRequiredStop as stop:
        result = stop.result
        if result.get("journal") and result.get("manifest"):
            print(f"journal: {result['journal']}")
            print(f"public manifest: {result['manifest']}")
        return 2
    print(f"journal: {journal}")
    print(f"public manifest: {manifest}")
    return 0


__all__ = [
    "BRIDGE_HOST",
    "BRIDGE_PORT",
    "CANONICAL_EFFECT_ACTION",
    "BridgeBindingFailure",
    "CAPTURE_HASH_MISMATCH",
    "CAPTURE_REFUSED",
    "CLEANUP_FAILED",
    "CleanupFailure",
    "DEFAULT_CAPTURE_TIMEOUT",
    "DEFAULT_COMMAND_TIMEOUT",
    "DEFAULT_EFFECT_TIMEOUT",
    "DEFAULT_HASH_TIMEOUT",
    "DEFAULT_TOTAL_TIMEOUT",
    "FIXED_TEMP_PATHS",
    "JOURNAL_SCHEMA",
    "LiveRecoveryError",
    "MAX_CAPTURE_TIMEOUT",
    "MAX_COMMAND_TIMEOUT",
    "MAX_EFFECT_TIMEOUT",
    "MAX_HASH_TIMEOUT",
    "MAX_TOTAL_TIMEOUT",
    "PARAM_NODE_PATH",
    "PASS_ALREADY_LOW",
    "PASS_RECOVERED_LOW",
    "PAYLOAD_PATH",
    "PRE_EFFECT_PREFLIGHT_INCOMPLETE",
    "PUBLIC_SCHEMA",
    "RECOVERY_JOURNAL_SCHEMA",
    "RECOVERY_PUBLIC_SCHEMA",
    "RECOVERY_WRITE_REQUIRED_NOT_EXECUTED",
    "RecoveryStop",
    "RecoveryWriteRequired",
    "RecoveryWriteRequiredStop",
    "REPO_ROOT",
    "SAFE_ID_RE",
    "SOURCE_ACTIONS",
    "SOURCE_CLAIM_FAILED",
    "SMOKE_PATH",
    "TARGET",
    "LOW_VERIFIED_PENDING_CLEANUP",
    "coordinate_dlow_effect",
    "_cleanup_temp",
    "_cleanup_all",
    "_capture_preimage",
    "_fixed_paths",
    "_validate_timeout",
    "build_parser",
    "collect",
    "derive_paths",
    "derive_source_path",
    "execute",
    "fixed_output_paths",
    "fixed_source_journal_path",
    "main",
    "parse_cmdline",
    "preimage_path",
    "preimage_file_path",
    "private_journal_path",
    "public_manifest_path",
    "recovery_journal_path",
    "run",
    "source_journal_path",
    "_claim_source",
    "_ensure_source_unclaimed",
]


if __name__ == "__main__":
    raise SystemExit(main())
