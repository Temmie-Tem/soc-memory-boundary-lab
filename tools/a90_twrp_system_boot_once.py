#!/usr/bin/env python3
"""Boot the exact A90 TWRP target into System exactly once.

This is the durable Verification 024 owner for the code-only TWRP transition.
The older :mod:`a90_twrp_system_boot` module contains the small, finite-timeout
ADB primitives and proves the target-specific command sequence; this module
owns the transaction journal and therefore never calls its unjournaled
``dispatch_system_boot`` helper.

Only the fixed SM-A908N/r3q Recovery endpoint is admissible.  Preparation is
one ``tw_reboot_arg=system`` write followed by one exact readback, then a
separately journaled ``sync`` preparation.  The sole boot effect is one
``twrp set tw_gui_done 1`` command after a durable dispatch marker.  An
exception or incomplete disconnect observation is retained as a no-replay
reconciliation condition.

Importing this module performs no device discovery, subprocess launch, or
USB/ADB contact.  Tests replace the narrow runner and selector seams.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import inspect
import os
from pathlib import Path
import re
from typing import Callable, Mapping, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes
    from tools import a90_twrp_system_boot as twrp
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes  # type: ignore
    import a90_twrp_system_boot as twrp  # type: ignore


# The production tree and all transport values are fixed.  ``output_root`` is
# accepted only as an internal function seam for host-only tests; it is not a
# parser option and cannot be selected by an operator invoking this script.
REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = REPO_ROOT
DEFAULT_OUTPUT_ROOT = OUTPUT_ROOT
# Pin the only subprocess transport to the installed regular-file binary;
# neither PATH nor an embedding Namespace may select another executable.
ADB = "/usr/lib/android-sdk/platform-tools/adb"

PHASES = ("control", "read", "rollback")
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)

TARGET_MODEL = twrp.TARGET_MODEL
TARGET_DEVICE = twrp.TARGET_DEVICE
TARGET_SERIAL_SHA256 = twrp.TARGET_SERIAL_SHA256
TWRP_VERSION = twrp.TWRP_VERSION
SUBPROCESS_TIMEOUT_SEC = twrp.SUBPROCESS_TIMEOUT_SEC

# This is intentionally a module constant rather than a command-line value.
# ``wait_for_disconnect`` itself polls only ``adb devices`` and never probes
# any endpoint returned by that listing.
DISCONNECT_TIMEOUT_SEC = 20.0
DEFAULT_DISCONNECT_TIMEOUT_SEC = DISCONNECT_TIMEOUT_SEC

PREPARATION_COMMAND = "twrp set tw_reboot_arg system"
PREPARATION_READ_COMMAND = "twrp get tw_reboot_arg"
SYNC_COMMAND = "sync"
EFFECT_COMMAND = "twrp set tw_gui_done 1"
EFFECT_ARGV = ("twrp set tw_gui_done 1",)
_READONLY_SHELL_COMMANDS = frozenset(
    {
        "getprop ro.product.model",
        "getprop ro.product.device",
        "twrp --help 2>&1",
        "twrp get tw_gui_done",
        PREPARATION_READ_COMMAND,
        "cat /proc/sys/kernel/random/boot_id",
    }
)
_MUTATING_SHELL_COMMANDS = frozenset({PREPARATION_COMMAND, SYNC_COMMAND, EFFECT_COMMAND})

JOURNAL_SCHEMA = "sdm855-a90-twrp-system-boot-once-journal-v1"
PUBLIC_SCHEMA = "sdm855-a90-twrp-system-boot-once-public-v1"
EFFECT_CLAIM_SCHEMA = "sdm855-a90-twrp-system-effect-claim-v1"
EFFECT_CLAIM_PREFIX = "verification-024-twrp-system-effect-"
PRE_EFFECT_STATUS = "INTENT_DURABLE_PRE_EFFECT"
PREPARATION_STARTED_STATUS = "PREPARATION_DISPATCH_STARTED"
PREPARATION_RETURNED_STATUS = "PREPARATION_WRITE_RETURNED"
PREPARATION_VERIFIED_STATUS = "PREPARATION_VERIFIED"
PREPARATION_RECONCILIATION_STATUS = "PREPARATION_OUTCOME_AMBIGUOUS_RECONCILE_REQUIRED"
SYNC_PREPARATION_STARTED_STATUS = "SYNC_PREPARATION_DISPATCH_STARTED"
SYNC_PREPARATION_VERIFIED_STATUS = "SYNC_PREPARATION_VERIFIED"
SYNC_PREPARATION_RECONCILIATION_STATUS = "SYNC_PREPARATION_OUTCOME_AMBIGUOUS_RECONCILE_REQUIRED"
EFFECT_CLAIMED_STATUS = "PHYSICAL_EFFECT_CLAIMED_RECONCILIATION_REQUIRED"
DISPATCH_STARTED_STATUS = "EFFECT_DISPATCH_STARTED"
WAITING_STATUS = "EFFECT_ACCEPTED_WAITING_FOR_DISCONNECT"
SUCCESS_STATUS = "SYSTEM_BOOT_DISCONNECT_OBSERVED"
OBSERVATION_INCOMPLETE_STATUS = "EFFECT_DISPATCHED_OBSERVATION_INCOMPLETE"
RECONCILIATION_STATUS = "EFFECT_DISPATCHED_RECONCILIATION_REQUIRED"
REFUSED_STATUS = "REFUSED_PRE_EFFECT"

# Compatibility names make the one-way boundary obvious to callers that use
# the naming from the neighbouring one-shot owners.
AMBIGUOUS_AFTER_EFFECT_STATUS = RECONCILIATION_STATUS
NO_REPLAY_STATUS = RECONCILIATION_STATUS


# Re-export the fixed primitive seams without importing or calling the old
# unjournaled dispatch function.
AdbEndpoint = twrp.AdbEndpoint
parse_adb_devices = twrp.parse_adb_devices
parse_assignment = twrp.parse_assignment
select_exact_recovery = twrp.select_exact_recovery
wait_for_disconnect = twrp.wait_for_disconnect
run_text = twrp.run_text


def run_checked(argv: Sequence[str], *, timeout: float | None = None) -> str:
    """Transport seam that retains the base finite-timeout implementation."""

    if not argv or argv[0] != ADB:
        raise BootError("System boot accepts only the fixed adb executable")
    if timeout is None:
        return run_text(argv)
    return run_text(argv, timeout=timeout)


BootError = twrp.BootError


class PreparationError(BootError):
    """A preparation write/readback whose outcome cannot be reconciled here."""

    def __init__(
        self,
        message: str,
        *,
        write_receipt: Mapping[str, object] | None = None,
        read_receipt: Mapping[str, object] | None = None,
        read_attempted: bool = False,
    ) -> None:
        super().__init__(message)
        self.write_receipt = dict(write_receipt) if write_receipt is not None else None
        self.read_receipt = dict(read_receipt) if read_receipt is not None else None
        self.read_attempted = bool(read_attempted)


SystemBootError = BootError
BootOnceError = BootError
Runner = Callable[[Sequence[str]], str]
_TRANSACTION_CAPABILITY = object()


def _require_transaction_capability(capability: object | None) -> None:
    if capability is not _TRANSACTION_CAPABILITY:
        raise BootError(
            "TWRP mutation helper requires the internal durable collect transaction"
        )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _as_bytes(value: object, label: str = "command output") -> bytes:
    """Normalize runner output while retaining an exact private receipt."""

    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise BootError(f"{label} is not text output: {type(value).__name__}")


def _as_text(value: object, label: str = "command output") -> str:
    raw = _as_bytes(value, label)
    try:
        return raw.decode("utf-8").replace("\r", "")
    except UnicodeDecodeError as exc:
        raise BootError(f"{label} is not UTF-8 text") from exc


def _receipt(value: object, label: str = "command output") -> dict[str, object]:
    raw = _as_bytes(value, label)
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "sha256": sha256(raw),
        "size": len(raw),
    }


def _one_line(value: object, label: str) -> str:
    text = _as_text(value, label).strip()
    if not text or "\n" in text or "\r" in text or "\x00" in text:
        raise BootError(f"{label} is not one exact bounded value")
    return text


def _parse_boot_id(value: object) -> str:
    """Parse exactly UUID, UUID+LF, or UUID+CRLF from raw transport bytes."""

    raw = _as_bytes(value, "Recovery boot_id")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BootError("Recovery boot_id is not valid UTF-8") from exc
    if text.endswith("\r\n"):
        normalized = text[:-2]
    elif text.endswith("\n"):
        normalized = text[:-1]
    else:
        normalized = text
    if BOOT_ID_RE.fullmatch(normalized) is None:
        raise BootError(
            "Recovery boot_id must be exactly UUID, UUID+LF, or UUID+CRLF"
        )
    return normalized


def _reject_symlink_components(path: Path, label: str = "output") -> None:
    """Reject symlinked path components, including dangling links."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise BootError(f"{label} component must not be a symlink: {cursor}")
        if cursor == anchor:
            return
        cursor = cursor.parent


def _ensure_output_dirs(root: Path) -> tuple[Path, Path]:
    root = Path(root)
    _reject_symlink_components(root, "output root")
    private_dir = root / "evidence" / "private"
    public_dir = root / "evidence" / "manifests"
    _reject_symlink_components(private_dir, "private output")
    _reject_symlink_components(public_dir, "public output")
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    public_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    # Existing directories may have been created with a permissive umask or
    # by an older helper; make the intended boundaries explicit.
    os.chmod(private_dir, 0o700)
    os.chmod(public_dir, 0o755)
    return private_dir, public_dir


def _refuse_existing(path: Path, label: str = "output") -> None:
    """Refuse an existing result, symlink, or stale atomic-publication temp."""

    if path.exists() or path.is_symlink():
        raise BootError(f"{label} already exists; replay forbidden: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise BootError(
            f"{label} temporary already exists; replay forbidden: {temporary}"
        )


def _atomic_json(path: Path, value: object) -> bytes:
    """Publish one private journal revision durably without following links."""

    path = Path(path)
    _reject_symlink_components(path.parent, "journal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json_bytes(value)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise BootError(f"journal temporary already exists: {temporary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except OSError as exc:
        raise BootError(f"refusing to create journal temporary: {temporary}") from exc
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
    """Claim the final journal inode before any Recovery command."""

    path = Path(path)
    _reject_symlink_components(path.parent, "journal")
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
                raise BootError("short initial journal write")
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


def _system_effect_identity(boot_id: str) -> tuple[dict[str, object], str]:
    if BOOT_ID_RE.fullmatch(boot_id) is None:
        raise BootError("System effect Recovery boot_id is not an exact UUID")
    identity: dict[str, object] = {
        "schema": EFFECT_CLAIM_SCHEMA,
        "current_recovery_boot_id": boot_id,
        "transition": "twrp-system-boot",
        "preparation": PREPARATION_COMMAND,
        "effect": "twrp set tw_gui_done 1",
    }
    return identity, hashlib.sha256(json_bytes(identity)).hexdigest()


def _system_effect_claim_path(root: Path, key_sha256: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{64}", key_sha256) is None:
        raise BootError("System effect claim key is not exact")
    _reject_symlink_components(root, "effect claim root")
    claim_dir = Path(root).resolve(strict=False) / "evidence" / "private"
    _reject_symlink_components(claim_dir, "effect claim")
    claim_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(claim_dir, 0o700)
    path = claim_dir / f"{EFFECT_CLAIM_PREFIX}{key_sha256}.claim.json"
    _reject_symlink_components(path, "effect claim")
    return path


def _create_system_effect_claim(
    path: Path,
    *,
    identity: Mapping[str, object],
    key_sha256: str,
    experiment_id: str,
) -> bytes:
    if path.exists() or path.is_symlink():
        raise BootError("System physical effect claim already exists; replay forbidden")
    data = json_bytes(
        {
            "schema": EFFECT_CLAIM_SCHEMA,
            "effect_key_sha256": key_sha256,
            "effect_identity": dict(identity),
            "claimed_by_experiment_id": experiment_id,
            "effect_replayed": False,
            "created_utc": utc_now(),
        }
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BootError("short System effect claim write")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
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
    return data


def _write_new(path: Path, data: bytes, mode: int) -> None:
    """Write one fresh public file without following links or clobbering."""

    path = Path(path)
    _reject_symlink_components(path.parent, "manifest")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise BootError(f"refusing to clobber manifest: {path}") from exc
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BootError(f"short write while publishing manifest: {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


write_new = _write_new


def _resolve_root(args: argparse.Namespace) -> Path:
    # The evidence tree is an owner identity, not an operator selector.  Tests
    # replace ``REPO_ROOT`` itself when they need an isolated tree; a Namespace
    # output_root cannot create a second replay namespace.
    if hasattr(args, "output_root"):
        raise BootError(
            "output_root selector is disabled; System boot evidence is fixed under REPO_ROOT"
        )
    root_input = Path(REPO_ROOT)
    _reject_symlink_components(root_input, "output root")
    return root_input.resolve(strict=False)


def _output_paths(root: Path, experiment_id: str) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise BootError("invalid experiment ID")
    private_dir, public_dir = _ensure_output_dirs(root)
    journal_path = private_dir / f"{experiment_id}.journal.json"
    manifest_path = public_dir / f"{experiment_id}.manifest.json"
    _reject_symlink_components(journal_path, "journal")
    _reject_symlink_components(manifest_path, "manifest")
    # Both destinations and both stale temp names are checked before any
    # selector, subprocess, or other device-facing operation.
    _refuse_existing(journal_path, "journal")
    _refuse_existing(manifest_path, "manifest")
    return journal_path, manifest_path


def adb_shell(adb: str, serial: str, command: str, run: Runner | None = None) -> object:
    """Run one allow-listed shell command through the fixed transport seam.

    The two state-changing commands require the private durable transaction
    capability.  Keeping this guard at the shell seam prevents an exported
    compatibility helper from becoming an unjournaled mutation route.
    """

    if adb != ADB:
        raise BootError("TWRP shell accepts only the pinned adb transport")
    if command in _MUTATING_SHELL_COMMANDS:
        # The private mutation helpers pass the capability through the runner
        # seam below; ordinary direct callers cannot supply it positionally.
        raise BootError(
            "direct TWRP mutation is disabled; use the durable collector"
        )
    if command not in _READONLY_SHELL_COMMANDS:
        raise BootError("shell command is outside the fixed read-only allowlist")
    runner = run_checked if run is None else run
    return runner((adb, "-s", serial, "shell", command))


def _adb_shell_mutation(
    adb: str,
    serial: str,
    command: str,
    run: Runner,
    *,
    capability: object | None,
) -> object:
    if command not in _MUTATING_SHELL_COMMANDS:
        raise BootError("internal command is not a fixed TWRP mutation")
    _require_transaction_capability(capability)
    if adb != ADB:
        raise BootError("TWRP shell accepts only the pinned adb transport")
    return run((adb, "-s", serial, "shell", command))


def _endpoint_serial(endpoint: object) -> str:
    serial = getattr(endpoint, "serial", None)
    if not isinstance(serial, str) or not serial:
        raise BootError("selected Recovery endpoint has no serial")
    return serial


def _endpoint_hash(endpoint: object) -> str:
    serial = _endpoint_serial(endpoint)
    return hashlib.sha256(serial.encode("utf-8")).hexdigest()


def _validate_endpoint(endpoint: object) -> tuple[str, str]:
    serial = _endpoint_serial(endpoint)
    state = getattr(endpoint, "state", None)
    serial_hash = _endpoint_hash(endpoint)
    if state != "recovery":
        raise BootError(f"selected endpoint is not Recovery: {state!r}")
    if serial_hash != TARGET_SERIAL_SHA256:
        raise BootError("selected endpoint serial hash is not the pinned A90 identity")
    return serial, serial_hash


def _validate_twrp_help(value: object) -> dict[str, object]:
    text = _as_text(value, "TWRP help")
    if "TWRP openrecoveryscript command line tool" not in text:
        raise BootError("bound endpoint does not expose the expected TWRP CLI")
    versions = re.findall(r"TWRP\s+version\s+([^\s,]+)", text)
    if versions != [TWRP_VERSION]:
        raise BootError("bound endpoint TWRP version differs from the proved build")
    return {
        "version": TWRP_VERSION,
        "receipt": _receipt(value, "TWRP help"),
    }


def preflight_recovery(
    adb: str = ADB,
    *,
    run: Runner | None = None,
    require_reboot_arg: bool = False,
) -> tuple[object, dict[str, object]]:
    """Bind one exact Recovery endpoint and validate all pre-effect gates."""

    if adb != ADB:
        raise BootError("TWRP Recovery selection accepts only the pinned adb transport")
    runner = run_checked if run is None else run
    # ``select_exact_recovery`` performs the first enumeration and filters by
    # Recovery state, pinned serial hash, model, and device.  The explicit
    # checks below retain the exact values in the private journal and defend
    # against a replaced/test selector seam.
    # Reuse model/device responses from the selector when it is the real
    # primitive.  A mocked selector may not have issued those reads, in which
    # case the two fixed probes below fill the same receipt slots.  This keeps
    # a real run to one exact selector pass rather than needlessly re-probing
    # the bound endpoint.
    selected_outputs: dict[str, object] = {}

    def selector_runner(argv: Sequence[str]) -> object:
        output = runner(argv)
        call = tuple(argv)
        if call == (adb, "devices"):
            selected_outputs["adb devices"] = output
        if call and call[-1] in {
            "getprop ro.product.model",
            "getprop ro.product.device",
        }:
            selected_outputs[call[-1]] = output
        return output

    selector_for_signature: object = select_exact_recovery
    # ``unittest.mock`` exposes a callable ``side_effect``.  Inspecting that
    # callback as well keeps a narrow host-test selector seam compatible with
    # the older two-argument form without issuing a second enumeration.
    selector_side_effect = getattr(select_exact_recovery, "side_effect", None)
    if callable(selector_side_effect):
        selector_for_signature = selector_side_effect
    try:
        selector_parameters = inspect.signature(selector_for_signature).parameters
        selector_accepts_hash = (
            "expected_serial_sha256" in selector_parameters
            or any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in selector_parameters.values()
            )
        )
    except (TypeError, ValueError):
        # The production primitive has a normal signature.  A callable test
        # seam whose signature cannot be inspected is conservatively invoked
        # using that primitive's historical two-argument form.
        selector_accepts_hash = False
    if selector_accepts_hash:
        endpoint = select_exact_recovery(
            adb,
            run=selector_runner,
            expected_serial_sha256=TARGET_SERIAL_SHA256,
        )
    else:
        endpoint = select_exact_recovery(adb, run=selector_runner)
    serial, serial_hash = _validate_endpoint(endpoint)
    model_raw = selected_outputs.get("getprop ro.product.model")
    if model_raw is None:
        model_raw = adb_shell(adb, serial, "getprop ro.product.model", runner)
    device_raw = selected_outputs.get("getprop ro.product.device")
    if device_raw is None:
        device_raw = adb_shell(adb, serial, "getprop ro.product.device", runner)
    model = _one_line(model_raw, "product model")
    device = _one_line(device_raw, "product device")
    if model != TARGET_MODEL:
        raise BootError(f"bound endpoint model differs: {model!r}")
    if device != TARGET_DEVICE:
        raise BootError(f"bound endpoint device differs: {device!r}")
    help_raw = adb_shell(adb, serial, "twrp --help 2>&1", runner)
    help_info = _validate_twrp_help(help_raw)
    gui_raw = adb_shell(adb, serial, "twrp get tw_gui_done", runner)
    gui_done = parse_assignment(_as_text(gui_raw, "tw_gui_done"), "tw_gui_done")
    if gui_done != "0":
        raise BootError(f"tw_gui_done is not at the pre-effect value 0: {gui_done!r}")
    boot_id_raw = adb_shell(
        adb,
        serial,
        "cat /proc/sys/kernel/random/boot_id",
        runner,
    )
    boot_id = _parse_boot_id(boot_id_raw)
    reboot_arg_raw: object | None = None
    reboot_arg: str | None = None
    if require_reboot_arg:
        reboot_arg_raw = adb_shell(
            adb,
            serial,
            PREPARATION_READ_COMMAND,
            runner,
        )
        reboot_arg = parse_assignment(
            _as_text(reboot_arg_raw, "tw_reboot_arg"),
            "tw_reboot_arg",
        )
        if reboot_arg != "system":
            raise BootError(
                "tw_reboot_arg is not at the final pre-effect value system: "
                f"{reboot_arg!r}"
            )
    model_receipt = _receipt(model_raw, "product model")
    device_receipt = _receipt(device_raw, "product device")
    twrp_help_receipt = help_info["receipt"]
    gui_receipt = _receipt(gui_raw, "tw_gui_done")
    boot_id_receipt = _receipt(boot_id_raw, "Recovery boot_id")
    reboot_arg_receipt = (
        _receipt(reboot_arg_raw, "tw_reboot_arg")
        if reboot_arg_raw is not None
        else None
    )
    devices_receipt = (
        _receipt(selected_outputs["adb devices"], "adb devices")
        if "adb devices" in selected_outputs
        else None
    )
    return endpoint, {
        "serial": serial,
        "serial_sha256": serial_hash,
        "state": "recovery",
        "adb_devices_receipt": devices_receipt,
        "model": model,
        "device": device,
        "twrp_version": help_info["version"],
        "model_receipt": model_receipt,
        "device_receipt": device_receipt,
        "twrp_help_receipt": twrp_help_receipt,
        "model_sha256": model_receipt["sha256"],
        "device_sha256": device_receipt["sha256"],
        "twrp_help_sha256": twrp_help_receipt["sha256"],
        "tw_gui_done": gui_done,
        "tw_gui_done_receipt": gui_receipt,
        "tw_gui_done_sha256": gui_receipt["sha256"],
        "boot_id": boot_id,
        # Keep the raw transport receipt for private evidence, while the
        # semantic identity hash is over the exact normalized UUID value.
        "boot_id_receipt": boot_id_receipt,
        "boot_id_sha256": sha256(boot_id.encode("utf-8")),
        "tw_reboot_arg": reboot_arg,
        "tw_reboot_arg_receipt": reboot_arg_receipt,
        "tw_reboot_arg_sha256": (
            reboot_arg_receipt["sha256"] if reboot_arg_receipt is not None else None
        ),
    }


TARGET_BINDING_FIELDS = (
    "serial",
    "serial_sha256",
    "state",
    "model",
    "device",
    "twrp_version",
    "boot_id",
)


def _same_target_binding(
    initial: Mapping[str, object],
    current: Mapping[str, object],
) -> bool:
    """Compare only identity fields; receipts may legitimately differ."""

    for field in TARGET_BINDING_FIELDS:
        if field not in initial or field not in current:
            return False
        if initial[field] is None or current[field] is None:
            return False
        if not isinstance(initial[field], str) or not isinstance(current[field], str):
            return False
        if not initial[field] or not current[field]:
            return False
        if initial[field] != current[field]:
            return False
    return True


def revalidate_recovery(
    initial_target: Mapping[str, object],
    *,
    require_reboot_arg: bool = False,
) -> tuple[object, dict[str, object]]:
    """Re-enumerate and revalidate the same exact Recovery endpoint."""

    endpoint, current_target = preflight_recovery(
        ADB,
        run=run_checked,
        require_reboot_arg=require_reboot_arg,
    )
    if current_target.get("tw_gui_done") != "0":
        raise BootError("revalidated Recovery tw_gui_done is not exact zero")
    if require_reboot_arg and current_target.get("tw_reboot_arg") != "system":
        raise BootError(
            "revalidated Recovery tw_reboot_arg is not exact system"
        )
    if not _same_target_binding(initial_target, current_target):
        raise BootError("exact Recovery target binding drifted before the next effect")
    return endpoint, current_target


def _prepare_system_boot(
    adb: str,
    serial: str,
    run: Runner | None = None,
    *,
    capability: object | None = None,
) -> dict[str, object]:
    """Perform one fixed preparation write and one exact readback."""

    _require_transaction_capability(capability)
    runner = run_checked if run is None else run
    write_raw = _adb_shell_mutation(
        adb,
        serial,
        PREPARATION_COMMAND,
        runner,
        capability=capability,
    )
    write_receipt = _receipt(write_raw, PREPARATION_COMMAND)
    try:
        read_raw = adb_shell(adb, serial, PREPARATION_READ_COMMAND, runner)
    except BaseException as exc:
        raise PreparationError(
            f"{type(exc).__name__}: {exc}",
            write_receipt=write_receipt,
            read_attempted=True,
        ) from exc
    read_receipt = _receipt(read_raw, PREPARATION_READ_COMMAND)
    try:
        value = parse_assignment(_as_text(read_raw, "tw_reboot_arg"), "tw_reboot_arg")
    except BaseException as exc:
        raise PreparationError(
            f"{type(exc).__name__}: {exc}",
            write_receipt=write_receipt,
            read_receipt=read_receipt,
            read_attempted=True,
        ) from exc
    if value != "system":
        raise PreparationError(
            f"tw_reboot_arg verification failed: {value!r}",
            write_receipt=write_receipt,
            read_receipt=read_receipt,
            read_attempted=True,
        )
    return {
        "command": PREPARATION_COMMAND,
        "read_command": PREPARATION_READ_COMMAND,
        "write_receipt": write_receipt,
        "read_receipt": read_receipt,
        "readback": value,
    }


def _sync_system_boot(
    adb: str,
    serial: str,
    run: Runner | None = None,
    *,
    capability: object | None = None,
) -> dict[str, object]:
    """Flush the prepared Recovery state as a separately journaled step."""

    _require_transaction_capability(capability)
    runner = run_checked if run is None else run
    raw = _adb_shell_mutation(
        adb,
        serial,
        SYNC_COMMAND,
        runner,
        capability=capability,
    )
    return {
        "command": SYNC_COMMAND,
        "receipt": _receipt(raw, SYNC_COMMAND),
    }


def prepare_system_boot(
    adb: str,
    serial: str,
    run: Runner | None = None,
) -> dict[str, object]:
    """Refuse direct preparation outside the durable collect transaction."""

    del adb, serial, run
    _require_transaction_capability(None)
    raise AssertionError("unreachable")


def prepare_system_boot_once(
    adb: str,
    serial: str,
    run: Runner | None = None,
) -> dict[str, object]:
    """Compatibility refusal for the former public preparation helper."""

    del adb, serial, run
    _require_transaction_capability(None)
    raise AssertionError("unreachable")


def _dispatch_system_boot_once(
    adb: str,
    serial: str,
    run: Runner | None = None,
    *,
    capability: object | None = None,
) -> dict[str, object]:
    """Dispatch the sole GUI-main-loop exit command once.

    Journaling the dispatch marker belongs to :func:`collect`; this narrow
    helper deliberately performs exactly one transport invocation and has no
    retry path.
    """

    _require_transaction_capability(capability)
    runner = run_checked if run is None else run
    raw = _adb_shell_mutation(
        adb,
        serial,
        EFFECT_COMMAND,
        runner,
        capability=capability,
    )
    return {
        "command": EFFECT_COMMAND,
        "argv": list(EFFECT_ARGV),
        "receipt": _receipt(raw, EFFECT_COMMAND),
    }


def dispatch_system_boot_once(
    adb: str,
    serial: str,
    run: Runner | None = None,
) -> dict[str, object]:
    """Refuse direct effect dispatch outside the durable collect transaction."""

    del adb, serial, run
    _require_transaction_capability(None)
    raise AssertionError("unreachable")


# Compatibility refusal for the former public one-shot name.  The durable
# collector calls the private capability-gated implementation below.
def dispatch_once(
    adb: str,
    serial: str,
    run: Runner | None = None,
) -> dict[str, object]:
    del adb, serial, run
    _require_transaction_capability(None)
    raise AssertionError("unreachable")


validate_twrp_help = _validate_twrp_help


def _initial_journal(experiment_id: str, phase: str, started: str) -> dict[str, object]:
    return {
        "schema": JOURNAL_SCHEMA,
        "experiment_id": experiment_id,
        "phase": phase,
        "started_utc": started,
        "status": PRE_EFFECT_STATUS,
        "expected_target": {
            "model": TARGET_MODEL,
            "device": TARGET_DEVICE,
            "twrp_version": TWRP_VERSION,
            "serial_sha256": TARGET_SERIAL_SHA256,
        },
        "target": None,
        "target_verified": False,
        "revalidation_before_preparation": None,
        "revalidation_after_preparation_marker": None,
        "revalidation_before_sync": None,
        "revalidation_before_effect": None,
        "revalidation_after_effect_marker": None,
        "physical_effect_claim": {
            "claimed": False,
            "attempted": False,
            "key_sha256": None,
            "claim_path": None,
            "claim_sha256": None,
            "claim_size": None,
        },
        "preparation": {
            "command": PREPARATION_COMMAND,
            "read_command": PREPARATION_READ_COMMAND,
            "expected_value": "system",
            "write_count": 0,
            "read_count": 0,
            "read_attempt_count": 0,
            "dispatched": False,
            "verified": False,
            "replayed": False,
            "sync": {
                "command": SYNC_COMMAND,
                "status": "NOT_STARTED",
                "write_count": 0,
                "verified": False,
            },
        },
        "effect": {
            "command": EFFECT_COMMAND,
            "argv": list(EFFECT_ARGV),
            "dispatch_count": 0,
            "dispatched": False,
            "replayed": False,
        },
        "effect_dispatched": False,
        "effect_dispatch_count": 0,
        "dispatch_count": 0,
        "preparation_write_count": 0,
        "preparation_read_count": 0,
        "preparation_verified": False,
        "write_count": 0,
        "reboot_dispatched": False,
        "effect_replayed": False,
        "preparation_command": PREPARATION_COMMAND,
        "preparation_read_command": PREPARATION_READ_COMMAND,
        "effect_command": EFFECT_COMMAND,
        "effect_argv": list(EFFECT_ARGV),
        "classification": PRE_EFFECT_STATUS,
        "automatic_retries": False,
        "partition_writes": False,
        "other_adb_endpoints_untouched": True,
        "observation": {
            "method": "adb devices endpoint absence only",
            "timeout_sec": DISCONNECT_TIMEOUT_SEC,
            "disconnect_observed": False,
        },
        "error": None,
    }


def _public_manifest(journal: Mapping[str, object], journal_data: bytes) -> dict[str, object]:
    target_obj = journal.get("target")
    target = target_obj if isinstance(target_obj, Mapping) else {}
    target_verified = bool(journal.get("target_verified"))
    public_boot_id_sha256: str | None = None
    private_target_boot_id: str | None = None
    if target_verified:
        if not isinstance(target_obj, Mapping):
            raise BootError("verified System target is missing its private boot_id")
        boot_id = target_obj.get("boot_id")
        if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
            raise BootError(
                "verified System target boot_id must be one exact UUID string"
            )
        private_target_boot_id = boot_id
        # The public binding is over the normalized private journal value, not
        # over the raw command receipt (which may include a trailing newline).
        public_boot_id_sha256 = sha256(boot_id.encode("utf-8"))
    elif isinstance(target_obj, Mapping) and "boot_id" in target_obj:
        boot_id = target_obj.get("boot_id")
        if boot_id is not None and (
            not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None
        ):
            raise BootError("unverified System target boot_id is malformed")
        if isinstance(boot_id, str):
            private_target_boot_id = boot_id
            public_boot_id_sha256 = sha256(boot_id.encode("utf-8"))
    physical_obj = journal.get("physical_effect_claim")
    physical_claim = physical_obj if isinstance(physical_obj, Mapping) else {}
    public_physical_claim = {
        key: physical_claim.get(key)
        for key in (
            "claimed",
            "attempted",
            "key_sha256",
            "claim_sha256",
            "claim_size",
        )
        if key in physical_claim
    }
    if "boot_id" in physical_claim:
        private_claim_boot_id = physical_claim.get("boot_id")
        if (
            not isinstance(private_claim_boot_id, str)
            or BOOT_ID_RE.fullmatch(private_claim_boot_id) is None
        ):
            raise BootError("private System effect claim boot_id is malformed")
        if (
            private_target_boot_id is not None
            and private_claim_boot_id != private_target_boot_id
        ):
            raise BootError("private target and effect-claim boot_id differ")
        public_physical_claim["boot_id_sha256"] = sha256(
            private_claim_boot_id.encode("utf-8")
        )
    elif "claimed" in physical_claim and physical_claim.get("claimed") is not False:
        raise BootError("claimed System effect claim is missing its private boot_id")
    prep_obj = journal.get("preparation")
    preparation = prep_obj if isinstance(prep_obj, Mapping) else {}
    effect_obj = journal.get("effect")
    effect = effect_obj if isinstance(effect_obj, Mapping) else {}
    obs_obj = journal.get("observation")
    observation = obs_obj if isinstance(obs_obj, Mapping) else {}
    status = journal.get("status")
    error = journal.get("error")
    manifest: dict[str, object] = {
        "schema": PUBLIC_SCHEMA,
        "experiment_id": journal.get("experiment_id"),
        "phase": journal.get("phase"),
        "started_utc": journal.get("started_utc"),
        "completed_utc": journal.get("completed_utc"),
        "status": status,
        "classification": status,
        "target_verified": target_verified,
        "target_evaluation": "VERIFIED" if target_verified else "NOT_EVALUATED",
        "target_model": target.get("model") if target_verified else None,
        "target_device": target.get("device") if target_verified else None,
        "target_serial_sha256": target.get("serial_sha256") if target_verified else None,
        "twrp_version": target.get("twrp_version") if target_verified else None,
        "target": {
            "model": target.get("model") if target_verified else None,
            "device": target.get("device") if target_verified else None,
            "twrp_version": target.get("twrp_version") if target_verified else None,
            "serial_sha256": target.get("serial_sha256") if target_verified else None,
            "state": target.get("state") if target_verified else None,
            "boot_id_sha256": public_boot_id_sha256 if target_verified else None,
            "status": "VERIFIED" if target_verified else "NOT_EVALUATED",
        },
        "expected_target": {
            "model": TARGET_MODEL,
            "device": TARGET_DEVICE,
            "twrp_version": TWRP_VERSION,
            "serial_sha256": TARGET_SERIAL_SHA256,
            "state": "recovery",
        },
        "preflight": {
            "target_verified": target_verified,
            "tw_gui_done": target.get("tw_gui_done") if target_verified else None,
            "twrp_help_sha256": (
                target.get("twrp_help_receipt", {}).get("sha256")
                if target_verified and isinstance(target.get("twrp_help_receipt"), Mapping)
                else None
            ),
        },
        "preparation": {
            "command": PREPARATION_COMMAND,
            "read_command": PREPARATION_READ_COMMAND,
            "expected_value": "system",
            "write_count": preparation.get("write_count", 0),
            "read_count": preparation.get("read_count", 0),
            "verified": bool(preparation.get("verified")),
            "sync_command": SYNC_COMMAND,
            "sync_write_count": (
                preparation.get("sync", {}).get("write_count", 0)
                if isinstance(preparation.get("sync"), Mapping)
                else 0
            ),
            "sync_verified": (
                bool(preparation.get("sync", {}).get("verified"))
                if isinstance(preparation.get("sync"), Mapping)
                else False
            ),
            "sync_receipt_sha256": (
                preparation.get("sync", {}).get("receipt_sha256")
                if isinstance(preparation.get("sync"), Mapping)
                else None
            ),
        },
        "effect": {
            "command": EFFECT_COMMAND,
            "dispatch_count": effect.get("dispatch_count", 0),
            "write_count": journal.get("preparation_write_count", 0),
            "effect_dispatched_count": journal.get("effect_dispatch_count", 0),
            "effect_replayed": False,
        },
        "physical_effect_claim": public_physical_claim,
        "observation": {
            "method": "adb devices endpoint absence only",
            "timeout_sec": DISCONNECT_TIMEOUT_SEC,
            "disconnect_observed": bool(observation.get("disconnect_observed")),
        },
        "partition_writes": False,
        "partition_write": False,
        "dispatch_count": journal.get("dispatch_count", 0),
        "effect_dispatched_count": journal.get("effect_dispatch_count", 0),
        "preparation_verified": bool(journal.get("preparation_verified")),
        "effect_replayed": False,
        "raw_serial_omitted": True,
        "raw_commands_omitted": True,
        "raw_receipts_omitted": True,
        "other_adb_endpoints_untouched": True,
        "journal_sha256": sha256(journal_data),
        "journal_size": len(journal_data),
        "claims": {
            "PROVED": (
                [
                    "The exact pinned Recovery target was selected before the one-shot transaction."
                ]
                if target_verified
                else []
            ),
            "NO_REPLAY": [
                "The System boot effect has a durable dispatch count and is never retried."
            ],
        },
    }
    if isinstance(error, str) and error:
        # The exact error may contain private serial/argv data.  Retain only
        # its type in the public file.
        manifest["error_type"] = error.split(":", 1)[0]
    return manifest


def _observe_disconnect(endpoint: object) -> bool:
    """Invoke the fixed finite observer through a testable runner seam."""

    observer_for_signature: object = wait_for_disconnect
    observer_side_effect = getattr(wait_for_disconnect, "side_effect", None)
    if callable(observer_side_effect):
        observer_for_signature = observer_side_effect
    try:
        observer_parameters = inspect.signature(observer_for_signature).parameters
        accepts_runner = (
            "run" in observer_parameters
            or any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in observer_parameters.values()
            )
        )
    except (TypeError, ValueError):
        accepts_runner = True
    kwargs = {"run": run_checked} if accepts_runner else {}
    return bool(
        wait_for_disconnect(
            ADB,
            endpoint,
            DISCONNECT_TIMEOUT_SEC,
            **kwargs,
        )
    )


def observe_disconnect(endpoint: object) -> bool:
    return _observe_disconnect(endpoint)


def _publish_manifest(
    manifest_path: Path,
    journal: Mapping[str, object],
    journal_data: bytes,
) -> bytes:
    data = json_bytes(_public_manifest(journal, journal_data))
    write_new(manifest_path, data, 0o644)
    return data


def _journal_failure(
    journal_path: Path,
    manifest_path: Path,
    journal: dict[str, object],
    status: str,
    exc: BaseException,
) -> None:
    journal["status"] = status
    journal["classification"] = status
    journal["error"] = f"{type(exc).__name__}: {exc}"
    journal["completed_utc"] = utc_now()
    journal_data = _atomic_json(journal_path, journal)
    _publish_manifest(manifest_path, journal, journal_data)


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    """Run one fixed exact Recovery-to-System transition."""

    experiment_id = getattr(args, "experiment_id", None)
    phase = getattr(args, "phase", None)
    if not bool(getattr(args, "execute", False)):
        raise BootError("System boot requires explicit --execute")
    if not isinstance(experiment_id, str) or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise BootError("invalid experiment ID")
    if phase not in PHASES:
        raise BootError(f"phase must be one of {PHASES}: {phase!r}")
    if hasattr(args, "adb") and getattr(args, "adb") != ADB:
        raise BootError("System boot accepts only the fixed adb executable")

    root = _resolve_root(args)
    journal_path, manifest_path = _output_paths(root, experiment_id)
    started = utc_now()
    journal = _initial_journal(experiment_id, phase, started)
    # This first durable revision is written before target enumeration.  It
    # makes an interrupted preflight itself a replay-forbidden transaction.
    _create_initial_json(journal_path, journal)

    endpoint: object | None = None
    effect_claim_identity: dict[str, object] | None = None
    effect_claim_key_sha256: str | None = None
    effect_claim_path: Path | None = None
    effect_claim_data: bytes | None = None
    effect_claim_attempted = False
    effect_claimed = False
    try:
        endpoint, target = preflight_recovery(ADB, run=run_checked)
        journal["target"] = target
        journal["target_verified"] = True
        journal["target_serial_sha256"] = target["serial_sha256"]
        journal["target_model"] = target["model"]
        journal["target_device"] = target["device"]
        journal["twrp_version"] = target["twrp_version"]
        journal["tw_gui_done_before"] = target["tw_gui_done"]
        journal["status"] = PRE_EFFECT_STATUS
        journal["classification"] = PRE_EFFECT_STATUS
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        try:
            _journal_failure(journal_path, manifest_path, journal, REFUSED_STATUS, exc)
        except BaseException as publish_exc:
            raise BootError(
                f"pre-effect target gate failed ({type(exc).__name__}: {exc}); "
                f"evidence publication failed: {type(publish_exc).__name__}: {publish_exc}"
            ) from exc
        raise BootError(f"pre-effect target gate failed: {exc}") from exc

    assert endpoint is not None  # guarded by the successful preflight above
    initial_target = dict(target)

    # Re-enumerate the exact Recovery endpoint immediately before the first
    # TWRP state write.  This closes the gap in which the original selector
    # could become stale while host-side journal revisions were being made.
    try:
        endpoint, rebound_target = revalidate_recovery(initial_target)
        journal["revalidation_before_preparation"] = {
            "verified": True,
            "target_verified": True,
            "target": rebound_target,
            "require_reboot_arg": False,
        }
        boot_id = rebound_target.get("boot_id")
        if not isinstance(boot_id, str):
            raise BootError("Recovery boot_id is missing from the fresh preflight")
        effect_claim_identity, effect_claim_key_sha256 = _system_effect_identity(boot_id)
        effect_claim_path = _system_effect_claim_path(root, effect_claim_key_sha256)
        if effect_claim_path.exists() or effect_claim_path.is_symlink():
            raise BootError("System physical effect claim already exists; replay forbidden")
        effect_claim_attempted = True
        physical = journal.get("physical_effect_claim")
        if isinstance(physical, dict):
            physical.update(
                {
                    "attempted": True,
                    "key_sha256": effect_claim_key_sha256,
                    "claim_path": str(effect_claim_path),
                    "boot_id": boot_id,
                }
            )
        effect_claim_data = _create_system_effect_claim(
            effect_claim_path,
            identity=effect_claim_identity,
            key_sha256=effect_claim_key_sha256,
            experiment_id=experiment_id,
        )
        effect_claimed = True
        if isinstance(physical, dict):
            physical.update(
                {
                    "claimed": True,
                    "claim_sha256": hashlib.sha256(effect_claim_data).hexdigest(),
                    "claim_size": len(effect_claim_data),
                }
            )
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        journal["revalidation_before_preparation"] = {
            "verified": False,
            "target_verified": False,
            "require_reboot_arg": False,
            "error_type": type(exc).__name__,
        }
        if effect_claim_attempted:
            journal["status"] = EFFECT_CLAIMED_STATUS
            journal["classification"] = EFFECT_CLAIMED_STATUS
            physical = journal.get("physical_effect_claim")
            if isinstance(physical, dict):
                physical["claimed"] = effect_claimed or bool(
                    effect_claim_path and effect_claim_path.exists()
                )
        try:
            _journal_failure(
                journal_path,
                manifest_path,
                journal,
                EFFECT_CLAIMED_STATUS if effect_claim_attempted else REFUSED_STATUS,
                exc,
            )
        except BaseException as publish_exc:
            raise BootError(
                f"Recovery revalidation before preparation failed ({type(exc).__name__}: {exc}); "
                f"evidence publication failed: {type(publish_exc).__name__}: {publish_exc}"
            ) from exc
        raise BootError(
            f"Recovery revalidation before preparation failed; no TWRP state write was sent: {exc}"
        ) from exc

    serial = _endpoint_serial(endpoint)

    # The preparation write is itself journaled before invocation.  A timeout,
    # malformed response, or readback mismatch leaves write_count=1 and never
    # proceeds to the GUI exit effect.
    preparation = journal["preparation"]
    assert isinstance(preparation, dict)
    preparation.update(
        {
            "status": PREPARATION_STARTED_STATUS,
            "write_count": 1,
            "dispatched": True,
            "command": PREPARATION_COMMAND,
            "read_command": PREPARATION_READ_COMMAND,
        }
    )
    journal["preparation_write_count"] = 1
    journal["write_count"] = 1
    journal["status"] = PREPARATION_STARTED_STATUS
    journal["classification"] = PREPARATION_STARTED_STATUS
    _atomic_json(journal_path, journal)
    try:
        # The preparation marker is durable.  Freshly rebind the exact
        # Recovery target immediately after it and dispatch the tw_reboot_arg
        # mutation with no host fsync or device command between that bind and
        # the write.  A bind failure is conservative: the prepared operation
        # remains reconciliation-required and is never retried.
        preparation_endpoint, preparation_target = revalidate_recovery(
            initial_target
        )
        preparation_serial = _endpoint_serial(preparation_endpoint)
        prep_result = _prepare_system_boot(
            ADB,
            preparation_serial,
            run_checked,
            capability=_TRANSACTION_CAPABILITY,
        )
        endpoint = preparation_endpoint
        journal["revalidation_after_preparation_marker"] = {
            "verified": True,
            "target_verified": True,
            "target": preparation_target,
            "require_reboot_arg": False,
        }
        preparation.update(
            {
                "write_receipt": prep_result["write_receipt"],
                "read_receipt": prep_result["read_receipt"],
                "write_sha256": prep_result["write_receipt"]["sha256"],
                "read_sha256": prep_result["read_receipt"]["sha256"],
                "readback": prep_result["readback"],
                "read_count": 1,
                "read_attempt_count": 1,
                "status": PREPARATION_VERIFIED_STATUS,
                "verified": True,
            }
        )
        journal["preparation_read_count"] = 1
        journal["preparation_verified"] = True
        journal["status"] = PREPARATION_VERIFIED_STATUS
        journal["classification"] = PREPARATION_VERIFIED_STATUS
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        if isinstance(exc, PreparationError):
            if exc.write_receipt is not None:
                preparation["write_receipt"] = exc.write_receipt
                preparation["write_sha256"] = exc.write_receipt.get("sha256")
            if exc.read_receipt is not None:
                preparation["read_receipt"] = exc.read_receipt
                preparation["read_sha256"] = exc.read_receipt.get("sha256")
            if exc.read_attempted:
                preparation["read_attempt_count"] = 1
                preparation["read_count"] = 1
                journal["preparation_read_count"] = 1
        preparation["status"] = PREPARATION_RECONCILIATION_STATUS
        preparation["error_type"] = type(exc).__name__
        try:
            _journal_failure(
                journal_path,
                manifest_path,
                journal,
                PREPARATION_RECONCILIATION_STATUS,
                exc,
            )
        except BaseException as publish_exc:
            raise BootError(
                f"TWRP preparation outcome is ambiguous ({type(exc).__name__}: {exc}); "
                f"evidence publication failed: {type(publish_exc).__name__}: {publish_exc}"
            ) from exc
        raise BootError(
            f"TWRP preparation outcome is ambiguous; no boot effect was sent: {exc}"
        ) from exc

    # Flush the prepared Recovery state as its own durable preparation.  The
    # final GUI effect marker is not published until this return has been
    # observed and journaled.
    sync_record = preparation.get("sync")
    if not isinstance(sync_record, dict):
        raise BootError("System preparation sync record is missing")
    sync_record.update(
        {
            "status": SYNC_PREPARATION_STARTED_STATUS,
            "write_count": 1,
            "dispatched": True,
            "command": SYNC_COMMAND,
        }
    )
    journal["sync_write_count"] = 1
    journal["sync_command"] = SYNC_COMMAND
    journal["status"] = SYNC_PREPARATION_STARTED_STATUS
    journal["classification"] = SYNC_PREPARATION_STARTED_STATUS
    _atomic_json(journal_path, journal)
    try:
        # ``sync`` is stateful as well as the tw_reboot_arg write.  The
        # durable sync-attempt marker is therefore followed by a fresh exact
        # Recovery rebind, with no host fsync or other device command between
        # that final bind and the sync itself.  Keep the returned binding out
        # of the journal until the command has returned.
        sync_endpoint, sync_target = revalidate_recovery(
            initial_target,
            require_reboot_arg=True,
        )
        sync_serial = _endpoint_serial(sync_endpoint)
        sync_result = _sync_system_boot(
            ADB,
            sync_serial,
            run_checked,
            capability=_TRANSACTION_CAPABILITY,
        )
        endpoint = sync_endpoint
        journal["revalidation_before_sync"] = {
            "verified": True,
            "target_verified": True,
            "target": sync_target,
            "require_reboot_arg": True,
            "tw_reboot_arg": sync_target["tw_reboot_arg"],
        }
        sync_record.update(
            {
                "receipt": sync_result["receipt"],
                "receipt_sha256": sync_result["receipt"]["sha256"],
                "status": SYNC_PREPARATION_VERIFIED_STATUS,
                "verified": True,
            }
        )
        journal["sync_verified"] = True
        journal["status"] = SYNC_PREPARATION_VERIFIED_STATUS
        journal["classification"] = SYNC_PREPARATION_VERIFIED_STATUS
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        if journal.get("revalidation_before_sync") is None:
            journal["revalidation_before_sync"] = {
                "verified": False,
                "target_verified": False,
                "require_reboot_arg": True,
                "error_type": type(exc).__name__,
            }
        sync_record["status"] = SYNC_PREPARATION_RECONCILIATION_STATUS
        sync_record["error_type"] = type(exc).__name__
        _journal_failure(
            journal_path,
            manifest_path,
            journal,
            SYNC_PREPARATION_RECONCILIATION_STATUS,
            exc,
        )
        raise BootError(
            f"System preparation sync outcome is ambiguous; no boot effect was sent: {exc}"
        ) from exc

    # Re-enumerate again after the preparation readback and immediately before
    # the durable effect marker.  The final pre-effect pass includes one
    # exact ``tw_reboot_arg`` readback; after it returns, only host journal
    # publication occurs before the sole GUI-main-loop exit command.
    try:
        endpoint, final_target = revalidate_recovery(
            initial_target,
            require_reboot_arg=True,
        )
        journal["revalidation_before_effect"] = {
            "verified": True,
            "target_verified": True,
            "target": final_target,
            "require_reboot_arg": True,
            "tw_reboot_arg": final_target["tw_reboot_arg"],
        }
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        journal["revalidation_before_effect"] = {
            "verified": False,
            "target_verified": False,
            "require_reboot_arg": True,
            "error_type": type(exc).__name__,
        }
        try:
            _journal_failure(
                journal_path,
                manifest_path,
                journal,
                REFUSED_STATUS,
                exc,
            )
        except BaseException as publish_exc:
            raise BootError(
                f"Recovery revalidation before effect failed ({type(exc).__name__}: {exc}); "
                f"evidence publication failed: {type(publish_exc).__name__}: {publish_exc}"
            ) from exc
        raise BootError(
            f"Recovery revalidation before effect failed; no boot effect was sent: {exc}"
        ) from exc

    serial = _endpoint_serial(endpoint)

    # This durable marker is the one-way boundary.  It is written before the
    # sole GUI state transition, and the count remains one across every
    # exception below.  There is intentionally no automatic retry branch.
    effect = journal["effect"]
    assert isinstance(effect, dict)
    effect.update(
        {
            "status": DISPATCH_STARTED_STATUS,
            "dispatch_count": 1,
            "dispatched": True,
            "command": EFFECT_COMMAND,
            "argv": list(EFFECT_ARGV),
        }
    )
    journal["status"] = DISPATCH_STARTED_STATUS
    journal["classification"] = DISPATCH_STARTED_STATUS
    journal["effect_dispatched"] = True
    journal["effect_dispatch_count"] = 1
    journal["dispatch_count"] = 1
    journal["reboot_dispatched"] = True
    journal["effect_argv"] = list(EFFECT_ARGV)
    journal["effect_replayed"] = False
    _atomic_json(journal_path, journal)

    try:
        # Freshly rebind the exact Recovery target after the durable dispatch
        # marker and immediately before the sole GUI-main-loop exit.  The
        # returned binding is intentionally retained only after the effect
        # returns; no host fsync or device command is inserted between this
        # rebind and dispatch.
        post_marker_endpoint, post_marker_target = revalidate_recovery(
            initial_target,
            require_reboot_arg=True,
        )
        post_marker_serial = _endpoint_serial(post_marker_endpoint)
        effect_result = _dispatch_system_boot_once(
            ADB,
            post_marker_serial,
            run_checked,
            capability=_TRANSACTION_CAPABILITY,
        )
        # Retain the fresh binding only after the one-shot effect has
        # returned; this same exact endpoint is then used for the bounded
        # disconnect observation.
        endpoint = post_marker_endpoint
        journal["revalidation_after_effect_marker"] = {
            "verified": True,
            "target_verified": True,
            "target": post_marker_target,
            "require_reboot_arg": True,
            "tw_reboot_arg": post_marker_target["tw_reboot_arg"],
        }
        effect["receipt"] = effect_result["receipt"]
        effect["receipt_sha256"] = effect_result["receipt"]["sha256"]
        effect["returned"] = True
        effect["status"] = WAITING_STATUS
        journal["dispatch_receipt"] = effect_result["receipt"]
        journal["status"] = WAITING_STATUS
        journal["classification"] = WAITING_STATUS
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        effect["returned"] = False
        effect["status"] = RECONCILIATION_STATUS
        effect["error_type"] = type(exc).__name__
        try:
            _journal_failure(
                journal_path,
                manifest_path,
                journal,
                RECONCILIATION_STATUS,
                exc,
            )
        except BaseException as publish_exc:
            raise BootError(
                f"System boot effect outcome is ambiguous ({type(exc).__name__}: {exc}); "
                f"evidence publication failed: {type(publish_exc).__name__}: {publish_exc}"
            ) from exc
        raise BootError(
            f"System boot effect outcome is ambiguous; replay is forbidden: {exc}"
        ) from exc

    # Observation is deliberately limited to disappearance of the bound
    # serial.  ``wait_for_disconnect`` enumerates but never probes an
    # unmatched endpoint, and this owner performs no post-disconnect command.
    try:
        disconnected = observe_disconnect(endpoint)
    except BaseException as exc:
        observation = journal["observation"]
        assert isinstance(observation, dict)
        observation["disconnect_observed"] = False
        observation["error_type"] = type(exc).__name__
        effect["status"] = RECONCILIATION_STATUS
        try:
            _journal_failure(
                journal_path,
                manifest_path,
                journal,
                RECONCILIATION_STATUS,
                exc,
            )
        except BaseException as publish_exc:
            raise BootError(
                f"System boot observation is incomplete ({type(exc).__name__}: {exc}); "
                f"evidence publication failed: {type(publish_exc).__name__}: {publish_exc}"
            ) from exc
        raise BootError(
            f"System boot observation is incomplete after one dispatch: {exc}"
        ) from exc

    observation = journal["observation"]
    assert isinstance(observation, dict)
    observation["disconnect_observed"] = disconnected
    if not disconnected:
        effect["status"] = OBSERVATION_INCOMPLETE_STATUS
        error = BootError(
            "System boot effect was accepted once but the bound endpoint did not "
            "disconnect within the fixed observation window; replay is forbidden"
        )
        try:
            _journal_failure(
                journal_path,
                manifest_path,
                journal,
                OBSERVATION_INCOMPLETE_STATUS,
                error,
            )
        except BaseException as publish_exc:
            raise BootError(
                f"{error}; evidence publication failed: "
                f"{type(publish_exc).__name__}: {publish_exc}"
            ) from error
        raise error

    journal["completed_utc"] = utc_now()
    journal["status"] = SUCCESS_STATUS
    journal["classification"] = SUCCESS_STATUS
    effect["status"] = SUCCESS_STATUS
    journal_data = _atomic_json(journal_path, journal)
    _publish_manifest(manifest_path, journal, journal_data)
    return journal_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--execute", action="store_true")
    return parser


def make_parser() -> argparse.ArgumentParser:
    return build_parser()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    journal_path, manifest_path = collect(args)
    print(f"journal: {journal_path}")
    print(f"public manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ADB",
    "AdbEndpoint",
    "AMBIGUOUS_AFTER_EFFECT_STATUS",
    "BootError",
    "BootOnceError",
    "DEFAULT_DISCONNECT_TIMEOUT_SEC",
    "DEFAULT_OUTPUT_ROOT",
    "DISCONNECT_TIMEOUT_SEC",
    "DISPATCH_STARTED_STATUS",
    "EFFECT_ARGV",
    "EFFECT_COMMAND",
    "JOURNAL_SCHEMA",
    "OBSERVATION_INCOMPLETE_STATUS",
    "OUTPUT_ROOT",
    "PHASES",
    "PRE_EFFECT_STATUS",
    "PREPARATION_COMMAND",
    "PreparationError",
    "PREPARATION_READ_COMMAND",
    "PREPARATION_RECONCILIATION_STATUS",
    "PREPARATION_STARTED_STATUS",
    "PREPARATION_VERIFIED_STATUS",
    "PUBLIC_SCHEMA",
    "RECONCILIATION_STATUS",
    "REFUSED_STATUS",
    "TARGET_BINDING_FIELDS",
    "REPO_ROOT",
    "SAFE_ID_RE",
    "SUBPROCESS_TIMEOUT_SEC",
    "SUCCESS_STATUS",
    "SystemBootError",
    "TARGET_DEVICE",
    "TARGET_MODEL",
    "TARGET_SERIAL_SHA256",
    "TWRP_VERSION",
    "adb_shell",
    "build_parser",
    "collect",
    "main",
    "make_parser",
    "observe_disconnect",
    "parse_adb_devices",
    "parse_assignment",
    "preflight_recovery",
    "revalidate_recovery",
    "run_checked",
    "run_text",
    "select_exact_recovery",
    "sha256",
    "validate_twrp_help",
    "wait_for_disconnect",
    "write_new",
]
