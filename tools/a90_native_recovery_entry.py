#!/usr/bin/env python3
"""Enter the exact A90 TWRP Recovery path once.

Verification 024 uses the native A90P1 ``recovery`` command to leave the
V2321 native image and enter the already-installed TWRP build.  This module is
deliberately only a recovery-entry owner.  It does not flash a partition,
invoke ``adb`` for a native command, or retry an ambiguous effect.

The command channel is intentionally self-contained here.  Read-only native
preflight frames use the small A90P1 reader from :mod:`a90_acm_snapshot`, but
the one ``CMD_NO_DONE`` effect has its own bounded socket loop because a
successful recovery command tears down the native USB channel before an END
frame can be emitted.

Importing this module performs no bridge validation, socket connection,
subprocess launch, or device discovery.  Tests replace the narrow transport
and validation seams below; production values are fixed constants.
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
import socket
import stat
import sys
import time
from typing import Any, Callable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, parse_fields
    from tools.a90_autohud_arbitration import run_stophud
    from tools.a90_pa28_live import validate_bridge_binding
    from tools.a90_twrp_system_boot import (
        TARGET_DEVICE as RECOVERY_TARGET_DEVICE,
        TARGET_MODEL as RECOVERY_TARGET_MODEL,
        TARGET_SERIAL_SHA256,
        TWRP_VERSION,
        parse_adb_devices,
        select_exact_recovery,
        run_text as recovery_run_text,
    )
    from tools.a90_param_capture import (
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
    )
    from tools.a90_v024_physical_claim import (
        PhysicalClaimAlreadyExists,
        PhysicalClaimError,
        PhysicalClaimPartial,
        NATIVE_TRANSITION_CLAIM_PREFIX,
        NATIVE_TRANSITION_CLAIM_SCHEMA,
        claim_native_transition,
        create_native_transition_claim,
        native_transition_claim_identity,
        native_transition_claim_path,
        inspect_native_transition_claim,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, parse_fields  # type: ignore
    from a90_autohud_arbitration import run_stophud  # type: ignore
    from a90_pa28_live import validate_bridge_binding  # type: ignore
    from a90_twrp_system_boot import (  # type: ignore
        TARGET_DEVICE as RECOVERY_TARGET_DEVICE,
        TARGET_MODEL as RECOVERY_TARGET_MODEL,
        TARGET_SERIAL_SHA256,
        TWRP_VERSION,
        parse_adb_devices,
        select_exact_recovery,
        run_text as recovery_run_text,
    )
    from a90_param_capture import (  # type: ignore
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
    )
    from a90_v024_physical_claim import (  # type: ignore
        PhysicalClaimAlreadyExists,
        PhysicalClaimError,
        PhysicalClaimPartial,
        NATIVE_TRANSITION_CLAIM_PREFIX,
        NATIVE_TRANSITION_CLAIM_SCHEMA,
        claim_native_transition,
        create_native_transition_claim,
        native_transition_claim_identity,
        native_transition_claim_path,
        inspect_native_transition_claim,
    )


# Fixed operator-owned bridge and output locations.  There are no command-line
# overrides for these values: selecting another endpoint or output tree would
# invalidate the target/replay contract.
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 54321
# Pin the read-only Recovery-side probes to the installed regular-file ADB
# binary; the owner never accepts a caller-selected executable.
ADB = "/usr/lib/android-sdk/platform-tools/adb"
OUTPUT_ROOT = REPO_ROOT
DEFAULT_OUTPUT_ROOT = OUTPUT_ROOT

PHASES = ("control", "read", "rollback")
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")

EXPECTED_VERSION = "A90 Linux init 0.9.285"
EXPECTED_RUNTIME = "0.9.285"
EXPECTED_RUNTIME_BUILD = TARGET_RUNTIME
EXPECTED_BUILD = f"build={TARGET_RUNTIME}"
EXPECTED_MODEL = TARGET_MODEL
EXPECTED_SOC = TARGET_SOC
EXPECTED_BOOTLOADER = TARGET_BOOTLOADER
EXPECTED_KERNEL = TARGET_KERNEL
EXPECTED_SOC_ID = "339"  # Exact A90 SM8150 / SDM855 sysfs identity.
EXPECTED_SOC_IDS = frozenset({EXPECTED_SOC_ID, EXPECTED_SOC})
EXPECTED_FORCE_UPLOAD = "0x0"
EXPECTED_DUMP_SINK = "0x0"
EXPECTED_PANIC_ON_OOPS = "1"
EXPECTED_SELFTEST = {
    "passed": 11,
    "warn": 1,
    "fail": 0,
    "entries": 12,
}

# This is the exact command class emitted by the retained native image:
# CMD_DANGEROUS (0x4) | CMD_NO_DONE (0x10), one argument (the command name).
RECOVERY_ARGV = ("recovery",)
RECOVERY_COMMAND = "recovery"
RECOVERY_WIRE = b"\ncmdv1 recovery\n"
RECOVERY_MARKER = b"recovery: syncing and rebooting to recovery"
RECOVERY_BEGIN_RE = re.compile(
    rb"(?:^|\r?\n)A90P1 BEGIN (?P<fields>[^\r\n]+)\r?\n"
)
RECOVERY_MARKER_RE = re.compile(
    rb"(?:^|\r?\n)recovery: syncing and rebooting to recovery(?:\r?\n|$)"
)
RECOVERY_END_RE = re.compile(rb"(?:^|\r?\n)A90P1 END [^\r\n]+(?:\r?\n|$)")
RECOVERY_ANY_END_RE = re.compile(rb"(?:^|\r?\n)A90P1 END(?:[ \t]|\r?\n|$)")

MAX_DISPATCH_TRANSCRIPT_BYTES = 1024 * 1024
DISPATCH_CONNECT_TIMEOUT_SEC = 3.0
DISPATCH_RECEIVE_TICK_SEC = 0.25
MAX_DISPATCH_READ_ATTEMPTS = 512
DEFAULT_COMMAND_TIMEOUT_SEC = 15.0
DEFAULT_DISPATCH_TIMEOUT_SEC = 12.0
DEFAULT_RECOVERY_TIMEOUT_SEC = 240.0
DEFAULT_RECOVERY_POLL_INTERVAL_SEC = 2.0
MAX_RECOVERY_POLL_ATTEMPTS = 180
RECOVERY_SUBPROCESS_TIMEOUT_SEC = 120.0
SUBPROCESS_TIMEOUT_SEC = RECOVERY_SUBPROCESS_TIMEOUT_SEC
MIN_TIMEOUT_SEC = 0.001
MAX_DISPATCH_TIMEOUT_SEC = 120.0
MAX_RECOVERY_TIMEOUT_SEC = 600.0
MAX_RECOVERY_POLL_INTERVAL_SEC = 60.0

# A recovery command tears down the native USB channel.  Keep the socket
# mutation behind a private capability that is held only by ``collect`` after
# its durable dispatch marker has been published.  The public compatibility
# names below are refusal shims, not alternate mutation entry points.
_TRANSACTION_CAPABILITY = object()

# Public seam for the fixed Recovery subprocess owner.  Keep the executable
# check at this boundary as well as at the collector so a direct embedding
# call cannot reintroduce PATH-selected ADB.
def run_text(
    argv: Sequence[str], *, timeout: float = RECOVERY_SUBPROCESS_TIMEOUT_SEC
) -> str:
    if not argv or argv[0] != ADB:
        raise RecoveryEntryError("Recovery entry accepts only the fixed adb executable")
    return recovery_run_text(argv, timeout=timeout)

BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
SELFTEST_RE = re.compile(
    rb"(?m)^selftest:\s+pass=(?P<passed>[0-9]+)\s+"
    rb"warn=(?P<warn>[0-9]+)\s+fail=(?P<fail>[0-9]+)\s+"
    rb"duration=(?P<duration>[0-9]+)ms\s+entries=(?P<entries>[0-9]+)\s*$"
)
KNOWN_BARE_FLAGS = frozenset({"skip_initramfs", "rootwait", "ro"})
CMDLINE_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]+\Z")

JOURNAL_SCHEMA = "sdm855-a90-recovery-entry-journal-v1"
PUBLIC_SCHEMA = "sdm855-a90-recovery-entry-public-v1"
# Recovery and native reboot share one physical transition claim.  The public
# owner journals retain their distinct effect names, but the claim key is
# intentionally only the current native boot UUID plus the transition schema.
EFFECT_CLAIM_SCHEMA = NATIVE_TRANSITION_CLAIM_SCHEMA
EFFECT_CLAIM_PREFIX = NATIVE_TRANSITION_CLAIM_PREFIX
PRE_EFFECT_STATUS = "INTENT_DURABLE_PRE_EFFECT"
DISPATCH_STARTED_STATUS = "EFFECT_DISPATCH_STARTED"
WAITING_STATUS = "EFFECT_ACCEPTED_WAITING_FOR_RECOVERY"
SUCCESS_STATUS = "RECOVERY_OBSERVED"
REFUSED_STATUS = "REFUSED_PRE_EFFECT"
RECONCILIATION_STATUS = "EFFECT_DISPATCHED_RECONCILIATION_REQUIRED"
EFFECT_CLAIMED_STATUS = "PHYSICAL_EFFECT_CLAIMED_RECONCILIATION_REQUIRED"


class RecoveryEntryError(RuntimeError):
    """Any failure of the exact native-to-Recovery entry contract."""


class RecoveryDispatchError(RecoveryEntryError):
    """The one-shot CMD_NO_DONE receipt is absent or malformed."""

    def __init__(
        self,
        message: str,
        *,
        transcript: bytes = b"",
        disconnected: bool = False,
    ) -> None:
        super().__init__(message)
        self.transcript = transcript
        self.disconnected = disconnected


class RecoveryObservationError(RecoveryEntryError):
    """The exact pinned TWRP endpoint was not observed in the fixed bound."""


def _finite_timeout(value: object, name: str, maximum: float) -> float:
    """Return a finite positive timeout within the owner bound."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RecoveryEntryError(f"{name} is not numeric")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < MIN_TIMEOUT_SEC or numeric > maximum:
        raise RecoveryEntryError(
            f"{name} must be finite and in [{MIN_TIMEOUT_SEC}, {maximum}]"
        )
    return numeric


def _require_transaction_capability(capability: object | None) -> None:
    if capability is not _TRANSACTION_CAPABILITY:
        raise RecoveryDispatchError(
            "direct recovery mutation is disabled; use the durable collector"
        )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _reject_symlink_components(path: Path) -> None:
    """Reject symlinked components before any output is opened."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise RecoveryEntryError(f"output component must not be a symlink: {cursor}")
        if cursor == anchor:
            return
        cursor = cursor.parent


def _ensure_output_dirs(root: Path) -> tuple[Path, Path]:
    root = Path(root)
    _reject_symlink_components(root)
    private_dir = root / "evidence" / "private"
    public_dir = root / "evidence" / "manifests"
    _reject_symlink_components(private_dir)
    _reject_symlink_components(public_dir)
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    public_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    return private_dir, public_dir


def _refuse_existing(path: Path) -> None:
    """Refuse duplicate or stale output, including a leftover temp file."""

    if path.exists() or path.is_symlink():
        raise RecoveryEntryError(f"output already exists; replay forbidden: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RecoveryEntryError(
            f"output temporary already exists; replay forbidden: {temporary}"
        )


def _atomic_json(path: Path, value: object) -> bytes:
    """Durably publish a journal revision with no-follow temp creation."""

    path = Path(path)
    _reject_symlink_components(path.parent)
    data = json_bytes(value)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RecoveryEntryError(f"journal temporary already exists: {temporary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return data


def _create_initial_json(path: Path, value: object) -> bytes:
    """Claim the final journal inode before bridge/stophud/device contact."""

    path = Path(path)
    _reject_symlink_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    data = json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RecoveryEntryError("short initial journal write")
            view = view[written:]
        os.fsync(descriptor)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(descriptor)
    return data


def _recovery_effect_identity(boot_id: str) -> tuple[dict[str, object], str]:
    try:
        return native_transition_claim_identity(boot_id)
    except PhysicalClaimError as exc:
        raise RecoveryEntryError(str(exc)) from exc


def _recovery_effect_claim_path(root: Path, key_sha256: str) -> Path:
    try:
        # The shared path constructor also enforces no-follow components and
        # the fixed final filename.  Keep this owner-local shim for callers
        # and tests that inspect the old helper name.
        return native_transition_claim_path(Path(root), key_sha256)
    except PhysicalClaimError as exc:
        raise RecoveryEntryError(str(exc)) from exc


def _create_recovery_effect_claim(
    path: Path,
    *,
    identity: Mapping[str, object],
    key_sha256: str,
    experiment_id: str,
) -> bytes:
    try:
        return create_native_transition_claim(
            path,
            identity=identity,
            key_sha256=key_sha256,
            experiment_id=experiment_id,
            provenance={"owner_kind": "native-recovery", "effect": "cmdv1 recovery"},
        )
    except PhysicalClaimAlreadyExists as exc:
        raise RecoveryEntryError(
            "native Recovery physical effect claim already exists; replay forbidden"
        ) from exc
    except PhysicalClaimError as exc:
        raise RecoveryEntryError(str(exc)) from exc


def _bridge_bindings_match(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Compare bridge identity while ignoring validation time metadata."""

    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def _write_new(path: Path, data: bytes, mode: int) -> None:
    """Write a fresh regular file without following links or clobbering."""

    path = Path(path)
    _reject_symlink_components(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise RecoveryEntryError(f"refusing to clobber output: {path}") from exc
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RecoveryEntryError(f"short write while publishing {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# Publication seam kept explicit for host-only tests and sibling tools.
write_new = _write_new


def parse_cmdline(payload: bytes) -> dict[str, str]:
    """Parse the exact native cmdline and reject malformed/duplicate tokens."""

    try:
        text = payload.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise RecoveryEntryError("target cmdline is not ASCII") from exc
    if not text or "\x00" in text:
        raise RecoveryEntryError("target cmdline is empty or contains NUL")
    result: dict[str, str] = {}
    for token in text.split():
        if "=" not in token:
            if token not in KNOWN_BARE_FLAGS or token in result:
                raise RecoveryEntryError(f"malformed cmdline token: {token!r}")
            result[token] = ""
            continue
        key, value = token.split("=", 1)
        if CMDLINE_KEY_RE.fullmatch(key) is None or not value or key in result:
            raise RecoveryEntryError(f"malformed or duplicate cmdline token: {token!r}")
        result[key] = value
    if not result:
        raise RecoveryEntryError("target cmdline is empty")
    return result


def _one_line(payload: bytes, label: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise RecoveryEntryError(f"{label} is not ASCII") from exc
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise RecoveryEntryError(f"{label} is not one bounded text value")
    return value


def _zero_value(value: str, label: str) -> str:
    if value in {"0", "0x0", "0X0"}:
        return EXPECTED_FORCE_UPLOAD if label == "force_upload" else EXPECTED_DUMP_SINK
    raise RecoveryEntryError(f"{label} is not exact zero: {value!r}")


def parse_selftest(payload: bytes) -> dict[str, int]:
    matches = list(SELFTEST_RE.finditer(payload.replace(b"\r\n", b"\n")))
    if len(matches) != 1:
        raise RecoveryEntryError("selftest lacks exactly one summary")
    values = {key: int(value) for key, value in matches[0].groupdict().items()}
    expected = dict(EXPECTED_SELFTEST)
    expected["duration"] = values["duration"]
    if values != expected:
        raise RecoveryEntryError(f"selftest is not exact 11/1/0/12: {values}")
    return values


def validate_version(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise RecoveryEntryError("target version is not ASCII") from exc
    if "\x00" in text:
        raise RecoveryEntryError("target version contains NUL")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    expected = {
        "runtime": f"{EXPECTED_VERSION} ({EXPECTED_RUNTIME_BUILD})",
        "build": f"version: {EXPECTED_RUNTIME} {EXPECTED_BUILD}",
        "kernel": f"kernel: {EXPECTED_KERNEL}",
    }
    prefixes = {"runtime": "A90 Linux init ", "build": "version: ", "kernel": "kernel: "}
    for label, wanted in expected.items():
        matching = [line for line in lines if line.startswith(prefixes[label])]
        if matching != [wanted]:
            raise RecoveryEntryError(f"target {label} identity is not exact")
    return {
        "runtime": EXPECTED_RUNTIME,
        "build": EXPECTED_RUNTIME_BUILD,
        "kernel": EXPECTED_KERNEL,
    }


def validate_target(
    version_payload: bytes,
    cmdline_payload: bytes,
    soc_payload: bytes,
    boot_id_payload: bytes | None = None,
    panic_payload: bytes | None = None,
    selftest_payload: bytes | None = None,
    phase: str = "control",
) -> dict[str, object]:
    """Validate every pre-effect native identity and health gate."""

    if phase not in PHASES:
        raise RecoveryEntryError(f"unsupported phase: {phase!r}")
    version = validate_version(version_payload)
    cmdline = parse_cmdline(cmdline_payload)
    expected_cmdline = {
        "androidboot.em.model": EXPECTED_MODEL,
        "androidboot.bootloader": EXPECTED_BOOTLOADER,
    }
    for key, value in expected_cmdline.items():
        if cmdline.get(key) != value:
            raise RecoveryEntryError(f"target cmdline lacks exact {key}={value}")
    debug_level = cmdline.get("androidboot.debug_level")
    if debug_level not in {"0x4f4c", "0x494d"}:
        raise RecoveryEntryError(f"target cmdline has unsupported debug level: {debug_level!r}")
    force_upload = _zero_value(cmdline.get("androidboot.force_upload", ""), "force_upload")
    dump_sink = _zero_value(cmdline.get("sec_debug.dump_sink", ""), "dump_sink")
    soc_id = _one_line(soc_payload, "soc_id")
    if soc_id not in EXPECTED_SOC_IDS:
        raise RecoveryEntryError(
            f"target soc_id is not the exact SM8150 identity: {soc_id!r}"
        )
    boot_id: str | None = None
    if boot_id_payload is not None:
        boot_id = _one_line(boot_id_payload, "boot_id")
        if BOOT_ID_RE.fullmatch(boot_id) is None:
            raise RecoveryEntryError(f"boot_id is malformed: {boot_id!r}")
    panic_on_oops: int | None = None
    if panic_payload is not None:
        panic_text = _one_line(panic_payload, "panic_on_oops")
        if panic_text != EXPECTED_PANIC_ON_OOPS:
            raise RecoveryEntryError(f"panic_on_oops is not exact 1: {panic_text!r}")
        panic_on_oops = int(panic_text)
    selftest: dict[str, int] | None = None
    if selftest_payload is not None:
        selftest = parse_selftest(selftest_payload)
    return {
        "model": EXPECTED_MODEL,
        "soc": EXPECTED_SOC,
        "soc_id": soc_id,
        "runtime": version["runtime"],
        "runtime_build": version["build"],
        "kernel": version["kernel"],
        "bootloader": EXPECTED_BOOTLOADER,
        "debug_level": debug_level,
        "force_upload": force_upload,
        "dump_sink": dump_sink,
        "boot_id": boot_id,
        "panic_on_oops": panic_on_oops,
        "selftest": selftest,
        "phase": phase,
    }


def _frame_record(evidence_id: str, argv: Sequence[str], frame: Any) -> dict[str, object]:
    payload = getattr(frame, "payload", b"")
    transcript = getattr(frame, "transcript", b"")
    if not isinstance(payload, bytes):
        payload = b""
    if not isinstance(transcript, bytes):
        transcript = b""
    return {
        "evidence_id": evidence_id,
        "argv": list(argv),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": sha256(payload),
        "payload_size": len(payload),
        "transcript_sha256": sha256(transcript),
        "transcript_size": len(transcript),
        "begin": dict(getattr(frame, "begin", {})),
        "end": dict(getattr(frame, "end", {})),
    }


def _read_frame(
    evidence_id: str,
    argv: tuple[str, ...],
    timeout: float,
    frames: list[dict[str, object]],
) -> Any:
    timeout = _finite_timeout(timeout, "native command timeout", MAX_DISPATCH_TIMEOUT_SEC)
    frame = exchange(
        BRIDGE_HOST,
        BRIDGE_PORT,
        Command(evidence_id, argv),
        timeout,
    )
    frames.append(_frame_record(evidence_id, argv, frame))
    return frame


def _preflight(
    phase: str,
    timeout: float,
    frames: list[dict[str, object]],
) -> dict[str, object]:
    commands = (
        ("version_before", ("version",)),
        ("cmdline_before", ("cat", "/proc/cmdline")),
        ("soc_id_before", ("cat", "/sys/devices/soc0/soc_id")),
        ("boot_id_before", ("cat", "/proc/sys/kernel/random/boot_id")),
        ("panic_on_oops_before", ("cat", "/proc/sys/kernel/panic_on_oops")),
        ("selftest_before", ("selftest", "status")),
    )
    payloads: dict[str, bytes] = {}
    for evidence_id, argv in commands:
        frame = _read_frame(evidence_id, argv, timeout, frames)
        payloads[evidence_id] = frame.payload
    target = validate_target(
        payloads["version_before"],
        payloads["cmdline_before"],
        payloads["soc_id_before"],
        payloads["boot_id_before"],
        payloads["panic_on_oops_before"],
        payloads["selftest_before"],
        phase=phase,
    )
    target["cmdline_raw"] = payloads["cmdline_before"]
    target["version_raw"] = payloads["version_before"]
    target["soc_id_raw"] = payloads["soc_id_before"]
    target["boot_id_raw"] = payloads["boot_id_before"]
    target["panic_raw"] = payloads["panic_on_oops_before"]
    target["selftest_raw"] = payloads["selftest_before"]
    return target


def _dispatch_descriptor(
    transcript: bytes,
    *,
    disconnected: bool,
    begin_observed: bool = False,
    marker_observed: bool = False,
    error: str | None = None,
) -> dict[str, object]:
    descriptor: dict[str, object] = {
        "a90p1_begin_observed": bool(begin_observed),
        "recovery_marker_observed": bool(marker_observed),
        "marker_observed": bool(marker_observed),
        "socket_disconnect_observed": bool(disconnected),
        "transcript_base64": base64.b64encode(transcript).decode("ascii"),
        "transcript_sha256": sha256(transcript),
        "transcript_size": len(transcript),
    }
    if error is not None:
        descriptor["error"] = error
    return descriptor


def validate_recovery_transcript(transcript: bytes) -> dict[str, object]:
    """Require exactly one CMD_NO_DONE BEGIN and the fixed recovery marker."""

    if not isinstance(transcript, bytes):
        raise RecoveryDispatchError("recovery transcript is not bytes")
    if len(transcript) > MAX_DISPATCH_TRANSCRIPT_BYTES:
        raise RecoveryDispatchError("recovery transcript exceeds fixed bound")
    begins = list(RECOVERY_BEGIN_RE.finditer(transcript))
    if len(begins) != 1:
        raise RecoveryDispatchError(
            f"recovery transcript has {len(begins)} A90P1 BEGIN records",
            transcript=transcript,
        )
    try:
        fields = parse_fields(begins[0].group("fields"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RecoveryDispatchError(
            "recovery BEGIN fields are malformed", transcript=transcript
        ) from exc
    if set(fields) != {"seq", "cmd", "argc", "flags"}:
        raise RecoveryDispatchError(
            "recovery BEGIN fields are not the exact retained protocol",
            transcript=transcript,
        )
    if fields.get("cmd") != "recovery":
        raise RecoveryDispatchError(
            f"recovery BEGIN command is not exact: {fields.get('cmd')!r}",
            transcript=transcript,
        )
    if fields.get("argc") != "1":
        raise RecoveryDispatchError(
            f"recovery BEGIN argc is not exact: {fields.get('argc')!r}",
            transcript=transcript,
        )
    # Retain the exact wire spelling as well as the value.  Numeric aliases
    # such as ``20`` would describe the same bit mask but are not the proved
    # CMD_NO_DONE receipt emitted by the native owner.
    if fields.get("flags") != "0x14":
        raise RecoveryDispatchError(
            f"recovery BEGIN flags are not CMD_NO_DONE 0x14: {fields.get('flags')!r}",
            transcript=transcript,
        )
    if (
        "seq" not in fields
        or not fields["seq"].isdigit()
        or (len(fields["seq"]) > 1 and fields["seq"].startswith("0"))
    ):
        raise RecoveryDispatchError("recovery BEGIN sequence is malformed", transcript=transcript)
    marker_matches = list(RECOVERY_MARKER_RE.finditer(transcript))
    if len(marker_matches) != 1:
        raise RecoveryDispatchError(
            f"recovery transcript has {len(marker_matches)} exact reboot markers",
            transcript=transcript,
        )
    marker_match = marker_matches[0]
    if RECOVERY_ANY_END_RE.search(transcript) is not None:
        raise RecoveryDispatchError(
            "recovery CMD_NO_DONE unexpectedly emitted an END frame",
            transcript=transcript,
        )
    if begins[0].start() >= marker_match.start():
        raise RecoveryDispatchError(
            "recovery marker appeared before the exact BEGIN record",
            transcript=transcript,
        )
    return {
        "a90p1_begin_observed": True,
        "recovery_marker_observed": True,
        "marker_observed": True,
        "begin": fields,
        "transcript_sha256": sha256(transcript),
        "transcript_size": len(transcript),
    }


def _socket_dispatch(
    host: str,
    port: int,
    timeout: float,
    *,
    socket_factory: Callable[..., Any] | None = None,
    clock: Callable[[], float] | None = None,
    capability: object | None = None,
) -> tuple[bytes, bool]:
    """Send the fixed recovery wire once and collect bounded receipt bytes."""

    _require_transaction_capability(capability)
    if host != BRIDGE_HOST or port != BRIDGE_PORT:
        raise RecoveryDispatchError("recovery accepts only the pinned loopback bridge")
    try:
        timeout = _finite_timeout(
            timeout, "recovery dispatch timeout", MAX_DISPATCH_TIMEOUT_SEC
        )
    except RecoveryEntryError as exc:
        raise RecoveryDispatchError(str(exc)) from exc
    if socket_factory is None:
        socket_factory = socket.create_connection
    if clock is None:
        clock = time.monotonic
    data = bytearray()
    disconnected = False
    read_attempts = 0
    try:
        sock = socket_factory(
            (BRIDGE_HOST, BRIDGE_PORT),
            timeout=min(float(timeout), DISPATCH_CONNECT_TIMEOUT_SEC),
        )
    except BaseException as exc:
        raise RecoveryDispatchError(f"recovery socket connect failed: {exc}") from exc
    try:
        try:
            sock.settimeout(min(DISPATCH_RECEIVE_TICK_SEC, float(timeout)))
            sock.sendall(RECOVERY_WIRE)
        except BaseException as exc:
            raise RecoveryDispatchError(
                f"recovery socket send failed: {exc}", transcript=bytes(data)
            ) from exc
        deadline = clock() + float(timeout)
        while clock() < deadline:
            if len(data) and len(data) > MAX_DISPATCH_TRANSCRIPT_BYTES:
                raise RecoveryDispatchError(
                    "recovery transcript exceeds fixed bound", transcript=bytes(data)
                )
            # A fake or broken monotonic source must not turn a bounded reader
            # into an infinite loop.  The real path is normally bounded first
            # by ``deadline``; this fixed attempt cap is a second guard.
            if read_attempts >= MAX_DISPATCH_READ_ATTEMPTS:
                break
            read_attempts += 1
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                # A timeout after the marker is a valid CMD_NO_DONE receipt;
                # before the marker it remains ambiguous and cannot be retried.
                if RECOVERY_MARKER in data:
                    return bytes(data), disconnected
                continue
            except (ConnectionResetError, BrokenPipeError, OSError):
                disconnected = True
                break
            if not chunk:
                disconnected = True
                break
            data.extend(chunk)
            if len(data) > MAX_DISPATCH_TRANSCRIPT_BYTES:
                raise RecoveryDispatchError(
                    "recovery transcript exceeds fixed bound", transcript=bytes(data)
                )
            # The recovery marker is emitted immediately before USB teardown.
            # Continue only until the peer closes or the bounded receive
            # deadline expires, preserving the exact bytes without expecting END.
        if RECOVERY_MARKER in data:
            return bytes(data), disconnected
        raise RecoveryDispatchError(
            "recovery dispatch timed out before the exact marker",
            transcript=bytes(data),
            disconnected=disconnected,
        )
    finally:
        try:
            sock.close()
        except BaseException:
            pass


def _dispatch_recovery_once(
    host: str = BRIDGE_HOST,
    port: int = BRIDGE_PORT,
    timeout: float = DEFAULT_DISPATCH_TIMEOUT_SEC,
    *,
    socket_factory: Callable[..., Any] | None = None,
    clock: Callable[[], float] | None = None,
    capability: object | None = None,
) -> dict[str, object]:
    """Dispatch one recovery command for the durable collector only."""

    _require_transaction_capability(capability)

    transcript, disconnected = _dispatch_once(
        host,
        port,
        timeout,
        socket_factory=socket_factory,
        clock=clock,
        capability=capability,
    )
    try:
        receipt = validate_recovery_transcript(transcript)
    except RecoveryDispatchError as exc:
        # Preserve marker/begin facts even when another exact field failed.
        exc.transcript = transcript
        exc.disconnected = disconnected
        raise RecoveryDispatchError(
            str(exc), transcript=transcript, disconnected=disconnected
        ) from exc
    receipt["socket_disconnect_observed"] = disconnected
    receipt["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
    return receipt


def _dispatch_once(
    host: str = BRIDGE_HOST,
    port: int = BRIDGE_PORT,
    timeout: float = DEFAULT_DISPATCH_TIMEOUT_SEC,
    *,
    socket_factory: Callable[..., Any] | None = None,
    clock: Callable[[], float] | None = None,
    capability: object | None = None,
) -> tuple[bytes, bool]:
    """Return raw bytes for the durable collector's one mutation."""

    _require_transaction_capability(capability)

    return _socket_dispatch(
        host,
        port,
        timeout,
        socket_factory=socket_factory,
        clock=clock,
        capability=capability,
    )


def dispatch_recovery_once(*args: Any, **kwargs: Any) -> dict[str, object]:
    """Refuse the historical direct recovery mutation before socket contact."""

    del args, kwargs
    _require_transaction_capability(None)
    raise AssertionError("unreachable")


def dispatch_once(*args: Any, **kwargs: Any) -> tuple[bytes, bool]:
    """Refuse the raw recovery mutation seam before socket contact."""

    del args, kwargs
    _require_transaction_capability(None)
    raise AssertionError("unreachable")


def _endpoint_serial_sha256(endpoint: Any) -> str:
    value = getattr(endpoint, "serial_sha256", None)
    if isinstance(value, str):
        return value
    serial = getattr(endpoint, "serial", None)
    if isinstance(serial, str):
        return sha256(serial.encode("utf-8"))
    return ""


def _endpoint_identity(endpoint: Any, run: Callable[[Sequence[str]], str]) -> dict[str, object]:
    serial = getattr(endpoint, "serial", None)
    state = getattr(endpoint, "state", None)
    if not isinstance(serial, str) or not serial:
        raise RecoveryObservationError("Recovery endpoint has no serial identity")
    if state != "recovery":
        raise RecoveryObservationError(f"bound endpoint state is not recovery: {state!r}")
    serial_hash = _endpoint_serial_sha256(endpoint)
    if serial_hash != TARGET_SERIAL_SHA256:
        raise RecoveryObservationError("Recovery endpoint serial hash is not the pinned A90 hash")
    try:
        help_text = run((ADB, "-s", serial, "shell", "twrp --help 2>&1"))
    except BaseException as exc:
        raise RecoveryObservationError(f"TWRP identity probe failed: {exc}") from exc
    if isinstance(help_text, bytes):
        help_bytes = help_text
        try:
            help_text = help_text.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RecoveryObservationError("TWRP identity is not UTF-8") from exc
    elif isinstance(help_text, str):
        help_bytes = help_text.encode("utf-8")
    else:
        raise RecoveryObservationError("TWRP identity probe returned a non-text value")
    if "TWRP openrecoveryscript command line tool" not in help_text:
        raise RecoveryObservationError("bound endpoint is not the expected TWRP CLI")
    if f"TWRP version {TWRP_VERSION}" not in help_text:
        raise RecoveryObservationError("bound endpoint TWRP version differs from the pinned build")
    return {
        "state": "recovery",
        "model": RECOVERY_TARGET_MODEL,
        "device": RECOVERY_TARGET_DEVICE,
        "twrp_version": TWRP_VERSION,
        "serial": serial,
        "serial_sha256": serial_hash,
        "twrp_help_sha256": sha256(help_bytes),
        "twrp_help_size": len(help_bytes),
        "other_endpoints_untouched": True,
    }


def wait_for_exact_recovery(
    timeout: float = DEFAULT_RECOVERY_TIMEOUT_SEC,
    poll_interval: float = DEFAULT_RECOVERY_POLL_INTERVAL_SEC,
    *,
    select_fn: Callable[..., Any] | None = None,
    run: Callable[[Sequence[str]], str] | None = None,
    clock: Callable[[], float] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
) -> tuple[Any, dict[str, object]]:
    """Poll only the exact Recovery selector within fixed finite bounds."""

    try:
        timeout = _finite_timeout(
            timeout, "Recovery observation timeout", MAX_RECOVERY_TIMEOUT_SEC
        )
        poll_interval = _finite_timeout(
            poll_interval,
            "Recovery poll interval",
            MAX_RECOVERY_POLL_INTERVAL_SEC,
        )
    except RecoveryEntryError as exc:
        raise RecoveryObservationError(str(exc)) from exc
    selector = select_exact_recovery if select_fn is None else select_fn
    runner = run_text if run is None else run
    if clock is None:
        clock = time.monotonic
    if sleep_fn is None:
        sleep_fn = time.sleep
    deadline = clock() + float(timeout)

    def bounded_runner(argv: Sequence[str]) -> str:
        """Keep each production subprocess within the outer observation bound."""

        if runner is not run_text:
            # Test seams and already-bounded callers retain their one-argument
            # contract; the selector itself remains exact-target-only.
            return runner(argv)
        remaining = deadline - clock()
        if remaining < MIN_TIMEOUT_SEC:
            raise RecoveryObservationError("Recovery observation deadline expired")
        # ``run_text`` is the fixed subprocess primitive.  Passing the
        # remaining budget prevents one 120-second child timeout from outliving
        # a shorter outer Recovery observation window.
        return run_text(argv, timeout=min(RECOVERY_SUBPROCESS_TIMEOUT_SEC, remaining))

    attempts = 0
    last_error = "no exact Recovery endpoint observed"
    while attempts < MAX_RECOVERY_POLL_ATTEMPTS and clock() < deadline:
        attempts += 1
        try:
            endpoint = selector(ADB, run=bounded_runner)
            identity = _endpoint_identity(endpoint, bounded_runner)
            identity["poll_attempts"] = attempts
            return endpoint, identity
        except RecoveryObservationError:
            raise
        except BaseException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        remaining = deadline - clock()
        if remaining <= 0:
            break
        sleep_fn(min(float(poll_interval), remaining))
    raise RecoveryObservationError(
        f"exact Recovery endpoint not observed within fixed bound: {last_error}; "
        f"attempts={attempts}"
    )


def _target_public(target: Mapping[str, object]) -> dict[str, object]:
    cmdline_raw = target.get("cmdline_raw", b"")
    version_raw = target.get("version_raw", b"")
    soc_raw = target.get("soc_id_raw", b"")
    boot_id_raw = target.get("boot_id_raw", b"")
    panic_raw = target.get("panic_raw", b"")
    selftest_raw = target.get("selftest_raw", b"")

    def descriptor(value: object) -> dict[str, object]:
        data = value if isinstance(value, bytes) else b""
        return {"sha256": sha256(data), "size": len(data)}

    return {
        "model": target.get("model"),
        "soc": target.get("soc"),
        "runtime": target.get("runtime"),
        "runtime_build": target.get("runtime_build"),
        "kernel": target.get("kernel"),
        "bootloader": target.get("bootloader"),
        "debug_level": target.get("debug_level"),
        "force_upload": target.get("force_upload"),
        "dump_sink": target.get("dump_sink"),
        "panic_on_oops": target.get("panic_on_oops"),
        "selftest": target.get("selftest"),
        "version": descriptor(version_raw),
        "cmdline": descriptor(cmdline_raw),
        "soc_id": descriptor(soc_raw),
        "boot_id": descriptor(boot_id_raw),
        "panic": descriptor(panic_raw),
        "selftest_evidence": descriptor(selftest_raw),
    }


def _public_manifest(
    *,
    experiment_id: str,
    phase: str,
    started: str,
    completed: str,
    status: str,
    target: Mapping[str, object] | None,
    journal_data: bytes,
    bridge_bound: bool,
    stophud: Mapping[str, object] | None,
    dispatch: Mapping[str, object] | None,
    recovery: Mapping[str, object] | None,
    effect_claim: Mapping[str, object] | None = None,
) -> dict[str, object]:
    target_public = _target_public(target) if target is not None else None
    dispatch_public = dict(dispatch) if dispatch is not None else None
    if dispatch_public is not None:
        dispatch_public.pop("begin", None)
        dispatch_public.pop("transcript_base64", None)
    recovery_public: dict[str, object] | None = None
    if recovery is not None:
        recovery_public = {
            key: value
            for key, value in recovery.items()
            if key not in {"serial", "serial_raw"}
        }
    return {
        "schema": PUBLIC_SCHEMA,
        "experiment_id": experiment_id,
        "phase": phase,
        "started_utc": started,
        "completed_utc": completed,
        "status": status,
        "target": target_public,
        "bridge": {
            "host": BRIDGE_HOST,
            "port": BRIDGE_PORT,
            "bound": bridge_bound,
            "serial_identity_omitted": True,
        },
        "stophud": {
            "accepted": bool(stophud and stophud.get("accepted")),
            "busy_retries": stophud.get("busy_retries", 0) if stophud else 0,
        },
        "effect": {
            "command": "cmdv1 recovery",
            "argv": list(RECOVERY_ARGV),
            "protocol": "A90P1 CMD_NO_DONE",
            "dispatch_count": 1 if dispatch is not None else 0,
            "effect_dispatched_count": 1 if dispatch is not None else 0,
            "effect_dispatched": dispatch is not None,
            "effect_replayed": False,
            "receipt": dispatch_public,
        },
        "physical_effect_claim": {
            key: effect_claim.get(key)
            for key in (
                "claimed",
                "attempted",
                "key_sha256",
                "claim_sha256",
                "claim_size",
                "boot_id",
            )
            if isinstance(effect_claim, Mapping) and key in effect_claim
        },
        "recovery": recovery_public,
        "dispatch_count": 1 if dispatch is not None else 0,
        "effect_replayed": False,
        "partition_write": False,
        "partition_writes": False,
        "raw_cmdline_omitted": True,
        "raw_transcript_omitted": True,
        "serial_omitted": True,
        "other_endpoints_untouched": bool(
            recovery is None or recovery.get("other_endpoints_untouched") is True
        ),
        "journal_sha256": sha256(journal_data),
        "journal_size": len(journal_data),
    }


def _write_failure_manifest(
    manifest_path: Path,
    *,
    experiment_id: str,
    phase: str,
    started: str,
    status: str,
    target: Mapping[str, object] | None,
    journal_data: bytes,
    bridge_bound: bool,
    stophud: Mapping[str, object] | None,
    dispatch: Mapping[str, object] | None,
    recovery: Mapping[str, object] | None,
    effect_claim: Mapping[str, object] | None = None,
) -> bytes:
    completed = utc_now()
    manifest = _public_manifest(
        experiment_id=experiment_id,
        phase=phase,
        started=started,
        completed=completed,
        status=status,
        target=target,
        journal_data=journal_data,
        bridge_bound=bridge_bound,
        stophud=stophud,
        dispatch=dispatch,
        recovery=recovery,
        effect_claim=effect_claim,
    )
    data = json_bytes(manifest)
    write_new(manifest_path, data, 0o644)
    return data


def _output_paths(root: Path, experiment_id: str) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise RecoveryEntryError("invalid experiment ID")
    private_dir, public_dir = _ensure_output_dirs(root)
    journal_path = private_dir / f"{experiment_id}.journal.json"
    manifest_path = public_dir / f"{experiment_id}.manifest.json"
    _reject_symlink_components(journal_path)
    _reject_symlink_components(manifest_path)
    _refuse_existing(journal_path)
    _refuse_existing(manifest_path)
    return journal_path, manifest_path


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    """Run one fixed recovery entry and publish private/public evidence."""

    experiment_id = getattr(args, "experiment_id", None)
    phase = getattr(args, "phase", None)
    execute = bool(getattr(args, "execute", False))
    if not execute:
        raise RecoveryEntryError("recovery entry requires explicit --execute")
    if not isinstance(experiment_id, str) or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise RecoveryEntryError("invalid experiment ID")
    if phase not in PHASES:
        raise RecoveryEntryError(f"phase must be one of {PHASES}: {phase!r}")
    if hasattr(args, "adb") and getattr(args, "adb") != ADB:
        raise RecoveryEntryError("Recovery entry accepts only the fixed adb executable")

    if hasattr(args, "output_root"):
        raise RecoveryEntryError(
            "output_root selector is disabled; Recovery evidence is fixed under REPO_ROOT"
        )
    root_input = Path(REPO_ROOT)
    _reject_symlink_components(root_input)
    root = root_input.resolve(strict=False)
    journal_path, manifest_path = _output_paths(root, experiment_id)
    started = utc_now()
    frames: list[dict[str, object]] = []
    stophud_frames: list[dict[str, object]] = []
    stophud_result: dict[str, object] | None = None
    target: dict[str, object] | None = None
    bridge_binding: Mapping[str, object] | None = None
    dispatch: dict[str, object] | None = None
    recovery: dict[str, object] | None = None
    effect_claim_identity: dict[str, object] | None = None
    effect_claim_key_sha256: str | None = None
    effect_claim_path: Path | None = None
    effect_claim_data: bytes | None = None
    effect_claim_attempted = False
    effect_claimed = False
    journal: dict[str, object] = {
        "schema": JOURNAL_SCHEMA,
        "experiment_id": experiment_id,
        "phase": phase,
        "started_utc": started,
        "status": PRE_EFFECT_STATUS,
        "expected_target": {
            "model": EXPECTED_MODEL,
            "soc": EXPECTED_SOC,
            "runtime": EXPECTED_RUNTIME_BUILD,
            "bootloader": EXPECTED_BOOTLOADER,
        },
        "target": None,
        "target_verified": False,
        "bridge_binding": None,
        "stophud": None,
        "arbitration": None,
        "stophud_frames": stophud_frames,
        "stophud_attempts": [],
        "frames": frames,
        "effect": "cmdv1 recovery",
        "effect_argv": list(RECOVERY_ARGV),
        "effect_dispatched": False,
        "effect_dispatch_count": 0,
        "effect_dispatched_count": 0,
        "dispatch_count": 0,
        "effect_replayed": False,
        "automatic_retries": False,
        "partition_writes": False,
        "physical_effect_claim": {
            "claimed": False,
            "attempted": False,
            "key_sha256": None,
            "claim_path": None,
            "claim_sha256": None,
            "claim_size": None,
            "boot_id": None,
        },
        "error": None,
    }
    # Claim the final journal path before bridge validation, stophud, or any
    # other device-facing operation.  A second owner loses at O_EXCL and can
    # never reach the effect dispatch.
    journal_data = _create_initial_json(journal_path, journal)

    def persist_stophud(attempts: list[dict[str, object]]) -> None:
        journal["status"] = "STOPHUD_IN_PROGRESS"
        journal["stophud_attempts"] = attempts
        journal["stophud_frames"] = stophud_frames
        _atomic_json(journal_path, journal)

    # Bridge validation is host-only; the first device command below is the
    # shared fixed stophud arbitration.  The initial journal is already
    # durable before this validation and before stophud's first frame.
    try:
        bridge_binding = validate_bridge_binding()
        if not isinstance(bridge_binding, Mapping):
            raise RecoveryEntryError("bridge binding validation returned no object")

        def bound_stophud_exchange(
            bound_host: str,
            bound_port: int,
            command: object,
            command_timeout: float,
            **kwargs: object,
        ) -> object:
            # The shared helper may retry only a complete busy refusal.  Bind
            # and compare the exact bridge immediately before every attempt,
            # including attempt two after a busy first response.
            current_binding = validate_bridge_binding()
            if not isinstance(current_binding, Mapping) or not _bridge_bindings_match(
                bridge_binding,
                current_binding,
            ):
                raise RecoveryEntryError(
                    "bridge binding drifted before stophud attempt"
                )
            return exchange(
                bound_host,
                bound_port,
                command,
                command_timeout,
                **kwargs,
            )

        stophud_result = run_stophud(
            BRIDGE_HOST,
            BRIDGE_PORT,
            DEFAULT_COMMAND_TIMEOUT_SEC,
            bound_stophud_exchange,
            frame_records=stophud_frames,
            persist=persist_stophud,
        )
        target = _preflight(phase, DEFAULT_COMMAND_TIMEOUT_SEC, frames)
    except BaseException as exc:
        # A target/preflight refusal has no recovery effect.  The initial
        # journal already owns the final path, so only an update is needed;
        # no second initial publication can race or clobber it.
        journal["completed_utc"] = utc_now()
        journal["status"] = REFUSED_STATUS
        journal["target"] = None
        journal["target_verified"] = False
        journal["bridge_binding"] = dict(bridge_binding) if bridge_binding else None
        journal["stophud"] = stophud_result
        journal["arbitration"] = stophud_result
        journal["stophud_frames"] = stophud_frames
        journal["frames"] = frames
        journal["error"] = f"{type(exc).__name__}: {exc}"
        try:
            journal_data = _atomic_json(journal_path, journal)
            _write_failure_manifest(
                manifest_path,
                experiment_id=experiment_id,
                phase=phase,
                started=started,
                status=REFUSED_STATUS,
                target=target,
                journal_data=journal_data,
                bridge_bound=bridge_binding is not None,
                stophud=stophud_result,
                dispatch=None,
                recovery=None,
                effect_claim=journal.get("physical_effect_claim"),
            )
        except BaseException as publish_exc:
            raise RecoveryEntryError(
                f"pre-effect refusal ({type(exc).__name__}: {exc}); evidence publication failed: "
                f"{type(publish_exc).__name__}: {publish_exc}"
            ) from exc
        raise RecoveryEntryError(f"pre-effect target gate failed: {exc}") from exc

    journal.update(
        {
            "status": PRE_EFFECT_STATUS,
            "target": {
                key: value
                for key, value in target.items()
                if key not in {
                    "cmdline_raw",
                    "version_raw",
                    "soc_id_raw",
                    "boot_id_raw",
                    "panic_raw",
                    "selftest_raw",
                }
            },
            "target_verified": True,
            "prestate": {
                "version_base64": base64.b64encode(target["version_raw"]).decode("ascii"),
                "cmdline_base64": base64.b64encode(target["cmdline_raw"]).decode("ascii"),
                "soc_id_base64": base64.b64encode(target["soc_id_raw"]).decode("ascii"),
                "boot_id_base64": base64.b64encode(target["boot_id_raw"]).decode("ascii"),
                "panic_on_oops_base64": base64.b64encode(target["panic_raw"]).decode("ascii"),
                "selftest_base64": base64.b64encode(target["selftest_raw"]).decode("ascii"),
                "version_sha256": sha256(target["version_raw"]),
                "cmdline_sha256": sha256(target["cmdline_raw"]),
                "soc_id_sha256": sha256(target["soc_id_raw"]),
                "boot_id_sha256": sha256(target["boot_id_raw"]),
                "panic_on_oops_sha256": sha256(target["panic_raw"]),
                "selftest_sha256": sha256(target["selftest_raw"]),
            },
            "bridge_binding": dict(bridge_binding),
            "bridge_binding_after_marker": None,
            "stophud": stophud_result,
            "arbitration": stophud_result,
            "stophud_frames": stophud_frames,
            "frames": frames,
            "effect": "cmdv1 recovery",
            "effect_argv": list(RECOVERY_ARGV),
            "effect_dispatched": False,
            "effect_dispatch_count": 0,
            "effect_dispatched_count": 0,
            "dispatch_count": 0,
            "effect_replayed": False,
            "automatic_retries": False,
            "partition_writes": False,
            "recovery": None,
        }
    )
    journal_data = _atomic_json(journal_path, journal)

    try:
        boot_id = target.get("boot_id")
        if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
            raise RecoveryEntryError("native Recovery effect boot_id is not exact")
        # Re-read the boot ID immediately before reserving the physical
        # transition so a claim cannot splice two native boot epochs.
        claim_frame = _read_frame(
            "boot_id_claim",
            ("cat", "/proc/sys/kernel/random/boot_id"),
            DEFAULT_COMMAND_TIMEOUT_SEC,
            frames,
        )
        claim_boot_id = _one_line(claim_frame.payload, "native Recovery claim boot_id")
        if BOOT_ID_RE.fullmatch(claim_boot_id) is None or claim_boot_id != boot_id:
            raise RecoveryEntryError("native Recovery boot_id changed before effect claim")
        effect_claim_identity, effect_claim_key_sha256 = _recovery_effect_identity(
            claim_boot_id
        )
        effect_claim_path = _recovery_effect_claim_path(
            root,
            effect_claim_key_sha256,
        )
        try:
            existing_claim = inspect_native_transition_claim(root, claim_boot_id)
        except PhysicalClaimPartial as exc:
            raise RecoveryEntryError(str(exc)) from exc
        if existing_claim is not None:
            raise RecoveryEntryError(
                "native Recovery physical effect claim already exists; replay forbidden"
            )
        effect_claim_attempted = True
        physical = journal.get("physical_effect_claim")
        if isinstance(physical, dict):
            physical.update(
                {
                    "attempted": True,
                    "key_sha256": effect_claim_key_sha256,
                    "claim_path": str(effect_claim_path),
                    "boot_id": claim_boot_id,
                }
            )
        try:
            claim = claim_native_transition(
                root,
                boot_id=claim_boot_id,
                experiment_id=experiment_id,
                provenance={
                    "owner_kind": "native-recovery",
                    "effect": "cmdv1 recovery",
                    "phase": phase,
                },
            )
        except PhysicalClaimAlreadyExists as exc:
            raise RecoveryEntryError(
                "native Recovery physical effect claim already exists; replay forbidden"
            ) from exc
        except PhysicalClaimError as exc:
            raise RecoveryEntryError(str(exc)) from exc
        effect_claim_data = claim.data
        effect_claimed = True
        if isinstance(physical, dict):
            physical.update(
                {
                    "claimed": True,
                    "claim_sha256": sha256(effect_claim_data),
                    "claim_size": len(effect_claim_data),
                }
            )
        journal["frames"] = frames
        journal_data = _atomic_json(journal_path, journal)
        # Revalidate the fixed host binding directly immediately before the
        # durable dispatch marker.  No generic or caller-selected endpoint is
        # accepted, and a drift is a pre-effect refusal.
        latest_binding = validate_bridge_binding()
        if not isinstance(latest_binding, Mapping) or not _bridge_bindings_match(
            bridge_binding, latest_binding
        ):
            raise RecoveryEntryError("bridge binding drifted before recovery dispatch")
        journal["bridge_binding_before_effect"] = dict(latest_binding)
        journal["status"] = DISPATCH_STARTED_STATUS
        journal["effect_dispatched"] = True
        journal["effect_dispatch_count"] = 1
        journal["effect_dispatched_count"] = 1
        journal["dispatch_count"] = 1
        journal["effect_replayed"] = False
        journal_data = _atomic_json(journal_path, journal)
    except BaseException as exc:
        journal["status"] = EFFECT_CLAIMED_STATUS if effect_claim_attempted else REFUSED_STATUS
        journal["error"] = f"{type(exc).__name__}: {exc}"
        physical = journal.get("physical_effect_claim")
        if isinstance(physical, dict):
            physical["claimed"] = effect_claimed or bool(
                effect_claim_path and effect_claim_path.exists()
            )
        journal_data = _atomic_json(journal_path, journal)
        _write_failure_manifest(
            manifest_path,
            experiment_id=experiment_id,
            phase=phase,
            started=started,
            status=EFFECT_CLAIMED_STATUS if effect_claim_attempted else REFUSED_STATUS,
            target=target,
            journal_data=journal_data,
            bridge_bound=True,
            stophud=stophud_result,
            dispatch=None,
            recovery=None,
            effect_claim=journal.get("physical_effect_claim"),
        )
        raise RecoveryEntryError(f"recovery refused before dispatch: {exc}") from exc

    # Exactly one invocation.  Any exception below leaves count=1 and is
    # permanently reconciliation-required; this block never resends.
    try:
        # Rebind the exact operator-owned bridge after the durable effect
        # marker and immediately before the one CMD_NO_DONE recovery effect.
        # No host fsync or other device command is inserted after this bind;
        # retain its returned identity only after the effect returns (or
        # conservatively omit it on an ambiguous failure).
        post_marker_binding = validate_bridge_binding()
        if not isinstance(post_marker_binding, Mapping) or not _bridge_bindings_match(
            latest_binding, post_marker_binding
        ):
            raise RecoveryEntryError("bridge binding drifted after recovery marker")
        dispatch = _dispatch_recovery_once(
            BRIDGE_HOST,
            BRIDGE_PORT,
            DEFAULT_DISPATCH_TIMEOUT_SEC,
            capability=_TRANSACTION_CAPABILITY,
        )
        journal["bridge_binding_after_marker"] = dict(post_marker_binding)
        journal["dispatch_receipt"] = dispatch
        journal["status"] = WAITING_STATUS
        journal_data = _atomic_json(journal_path, journal)
    except BaseException as exc:
        transcript = getattr(exc, "transcript", b"")
        disconnected = bool(getattr(exc, "disconnected", False))
        if not isinstance(transcript, bytes):
            transcript = b""
        # The durable marker already records dispatch_count=1 even when the
        # post-marker fresh bind failed before the socket call.  This empty
        # descriptor keeps public/private receipts aligned conservatively.
        dispatch = _dispatch_descriptor(
            transcript,
            disconnected=disconnected,
            begin_observed=RECOVERY_BEGIN_RE.search(transcript) is not None,
            marker_observed=RECOVERY_MARKER_RE.search(transcript) is not None,
            error=f"{type(exc).__name__}: {exc}",
        )
        journal["dispatch_receipt"] = dispatch
        journal["status"] = RECONCILIATION_STATUS
        journal["error"] = f"{type(exc).__name__}: {exc}"
        journal_data = _atomic_json(journal_path, journal)
        _write_failure_manifest(
            manifest_path,
            experiment_id=experiment_id,
            phase=phase,
            started=started,
            status=RECONCILIATION_STATUS,
            target=target,
            journal_data=journal_data,
            bridge_bound=True,
            stophud=stophud_result,
            dispatch=dispatch,
            recovery=None,
            effect_claim=journal.get("physical_effect_claim"),
        )
        raise RecoveryEntryError(
            f"recovery dispatch is ambiguous; journal requires reconciliation: {exc}"
        ) from exc

    try:
        observed = wait_for_exact_recovery()
        if (
            isinstance(observed, tuple)
            and len(observed) == 2
            and isinstance(observed[1], Mapping)
        ):
            endpoint, recovery = observed
        else:
            # Compatibility seam for tests/older callers that return only the
            # endpoint.  The production observer returns the richer pair and
            # has already performed the TWRP help/version probe.
            endpoint = observed
            serial = getattr(endpoint, "serial", None)
            serial_hash = _endpoint_serial_sha256(endpoint)
            if not isinstance(serial, str) or serial_hash != TARGET_SERIAL_SHA256:
                raise RecoveryObservationError("direct Recovery endpoint is not the pinned A90 identity")
            recovery = {
                "state": "recovery",
                "model": RECOVERY_TARGET_MODEL,
                "device": RECOVERY_TARGET_DEVICE,
                "twrp_version": TWRP_VERSION,
                "serial": serial,
                "serial_sha256": serial_hash,
                "twrp_identity_observed": True,
                "other_endpoints_untouched": True,
            }
        # Identity is retained in the private/public receipt.
        del endpoint
        journal["recovery"] = recovery
        journal["completed_utc"] = utc_now()
        journal["status"] = SUCCESS_STATUS
        journal_data = _atomic_json(journal_path, journal)
    except BaseException as exc:
        journal["status"] = RECONCILIATION_STATUS
        journal["error"] = f"{type(exc).__name__}: {exc}"
        journal_data = _atomic_json(journal_path, journal)
        _write_failure_manifest(
            manifest_path,
            experiment_id=experiment_id,
            phase=phase,
            started=started,
            status=RECONCILIATION_STATUS,
            target=target,
            journal_data=journal_data,
            bridge_bound=True,
            stophud=stophud_result,
            dispatch=dispatch,
            recovery=None,
            effect_claim=journal.get("physical_effect_claim"),
        )
        raise RecoveryEntryError(
            f"Recovery observation failed after one dispatch; reconciliation required: {exc}"
        ) from exc

    _write_failure_manifest(
        manifest_path,
        experiment_id=experiment_id,
        phase=phase,
        started=started,
        status=SUCCESS_STATUS,
        target=target,
        journal_data=journal_data,
        bridge_bound=True,
        stophud=stophud_result,
        dispatch=dispatch,
        recovery=recovery,
        effect_claim=journal.get("physical_effect_claim"),
    )
    return journal_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--execute", action="store_true")
    return parser


def make_parser() -> argparse.ArgumentParser:
    """Alias used by sibling runners and host-only tests."""

    return build_parser()


# Short aliases retained for callers that use the older runner naming.
wait_for_recovery = wait_for_exact_recovery
parse_recovery_transcript = validate_recovery_transcript


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    journal, manifest = collect(args)
    print(f"journal: {journal}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ADB",
    "BRIDGE_HOST",
    "BRIDGE_PORT",
    "DEFAULT_OUTPUT_ROOT",
    "DEFAULT_DISPATCH_TIMEOUT_SEC",
    "DEFAULT_RECOVERY_POLL_INTERVAL_SEC",
    "DEFAULT_RECOVERY_TIMEOUT_SEC",
    "EXPECTED_BOOTLOADER",
    "EXPECTED_BUILD",
    "EXPECTED_DUMP_SINK",
    "EXPECTED_FORCE_UPLOAD",
    "EXPECTED_KERNEL",
    "EXPECTED_MODEL",
    "EXPECTED_PANIC_ON_OOPS",
    "EXPECTED_RUNTIME",
    "EXPECTED_RUNTIME_BUILD",
    "EXPECTED_SELFTEST",
    "EXPECTED_SOC",
    "EXPECTED_SOC_ID",
    "EXPECTED_SOC_IDS",
    "EXPECTED_VERSION",
    "JOURNAL_SCHEMA",
    "MAX_RECOVERY_POLL_ATTEMPTS",
    "PHASES",
    "PUBLIC_SCHEMA",
    "RECOVERY_ARGV",
    "RECOVERY_COMMAND",
    "RECOVERY_MARKER",
    "RECOVERY_WIRE",
    "RecoveryDispatchError",
    "RecoveryEntryError",
    "RecoveryObservationError",
    "build_parser",
    "collect",
    "main",
    "make_parser",
    "parse_recovery_transcript",
    "parse_cmdline",
    "parse_selftest",
    "select_exact_recovery",
    "validate_recovery_transcript",
    "validate_target",
    "validate_version",
    "wait_for_exact_recovery",
    "wait_for_recovery",
    "run_text",
    "write_new",
]
