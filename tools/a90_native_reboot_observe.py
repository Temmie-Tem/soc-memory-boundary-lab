#!/usr/bin/env python3
"""Dispatch one exact A90 native reboot and prove the next boot identity.

``reboot`` is an A90P1 ``CMD_NO_DONE`` command: success tears down USB before
an END frame.  This tool therefore journals intent before sending the command,
sends it exactly once, never treats a timeout as permission to replay, and
qualifies success only from a changed boot ID plus exact post-boot runtime and
cmdline observations.  It does not flash or write a partition.
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
import socket
import time
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import (
        Command,
        exchange,
        json_bytes,
        parse_fields,
        write_new,
    )
    from tools.a90_autohud_arbitration import run_stophud
    from tools.a90_pa28_live import revalidate_bridge_binding, validate_bridge_binding
    from tools.a90_param_capture import (
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
        parse_cmdline,
        validate_runtime,
    )
    from tools.a90_runtime_health import parse_selftest
    from tools.a90_v024_physical_claim import (
        NATIVE_TRANSITION_CLAIM_PREFIX,
        NATIVE_TRANSITION_CLAIM_SCHEMA,
        PhysicalClaimAlreadyExists,
        PhysicalClaimError,
        PhysicalClaimPartial,
        claim_native_transition,
        create_native_transition_claim,
        inspect_native_transition_claim,
        native_transition_claim_identity,
        native_transition_claim_path,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import (  # type: ignore
        Command,
        exchange,
        json_bytes,
        parse_fields,
        write_new,
    )
    from a90_autohud_arbitration import run_stophud  # type: ignore
    from a90_pa28_live import (  # type: ignore
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    from a90_param_capture import (  # type: ignore
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
        parse_cmdline,
        validate_runtime,
    )
    from a90_runtime_health import parse_selftest  # type: ignore
    from a90_v024_physical_claim import (  # type: ignore
        NATIVE_TRANSITION_CLAIM_PREFIX,
        NATIVE_TRANSITION_CLAIM_SCHEMA,
        PhysicalClaimAlreadyExists,
        PhysicalClaimError,
        PhysicalClaimPartial,
        claim_native_transition,
        create_native_transition_claim,
        inspect_native_transition_claim,
        native_transition_claim_identity,
        native_transition_claim_path,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = REPO_ROOT
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REBOOT_BEGIN_RE = re.compile(
    rb"(?:^|\r?\n)A90P1 BEGIN (?P<fields>[^\r\n]+)\r?\n"
)
REBOOT_MARKER = b"reboot: syncing and restarting"
REBOOT_MARKER_RE = re.compile(
    rb"(?:^|\r?\n)reboot: syncing and restarting(?:\r?\n|$)"
)
REBOOT_END_RE = re.compile(rb"(?:^|\r?\n)A90P1 END [^\r\n]+(?:\r?\n|$)")
REBOOT_ANY_END_RE = re.compile(rb"(?:^|\r?\n)A90P1 END(?:[ \t]|\r?\n|$)")
MAX_DISPATCH_TRANSCRIPT_BYTES = 1024 * 1024
MAX_DISPATCH_READ_ATTEMPTS = 512
DISPATCH_CONNECT_TIMEOUT_SEC = 3.0
DISPATCH_RECEIVE_TICK_SEC = 0.25
REBOOT_WIRE = b"\ncmdv1 reboot\n"
# Native Recovery entry and native reboot share one physical transition claim
# namespace.  The owner journals keep their effect-specific provenance, while
# the claim key is only the current native boot UUID and transition schema.
EFFECT_CLAIM_SCHEMA = NATIVE_TRANSITION_CLAIM_SCHEMA
EFFECT_CLAIM_PREFIX = NATIVE_TRANSITION_CLAIM_PREFIX
EXPECTED_REBOOT_ARGC = "1"
EXPECTED_REBOOT_FLAGS = "0x14"
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
DEBUG_CMDLINE = {"low": "0x4f4c", "mid": "0x494d"}
EXPECTED_DEBUG_PREDECESSOR = {"low": "mid", "mid": "low"}

MIN_TIMEOUT_SEC = 0.001
MAX_COMMAND_TIMEOUT_SEC = 120.0
MAX_DISPATCH_TIMEOUT_SEC = 120.0
MAX_BOOT_TIMEOUT_SEC = 600.0
MAX_POLL_INTERVAL_SEC = 60.0
DEFAULT_COMMAND_TIMEOUT_SEC = 15.0
DEFAULT_DISPATCH_TIMEOUT_SEC = 10.0
DEFAULT_BOOT_TIMEOUT_SEC = 240.0
DEFAULT_POLL_INTERVAL_SEC = 2.0
_TRANSACTION_CAPABILITY = object()


class AvailabilityFrameError(RuntimeError):
    """A complete availability frame is malformed or reports a hard error."""


class AvailabilityBusy(AvailabilityFrameError):
    """A complete read-only availability frame was refused as busy."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _finite_timeout(value: object, name: str, maximum: float) -> float:
    """Validate one bounded positive timeout or polling interval."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite positive number")
    number = float(value)
    if not math.isfinite(number) or number < MIN_TIMEOUT_SEC or number > maximum:
        raise ValueError(
            f"{name} must be finite and in [{MIN_TIMEOUT_SEC}, {maximum}] seconds"
        )
    return number


def _validate_timeout_set(
    *,
    command_timeout: object,
    dispatch_timeout: object,
    boot_timeout: object,
    poll_interval: object,
) -> tuple[float, float, float, float]:
    return (
        _finite_timeout(command_timeout, "command timeout", MAX_COMMAND_TIMEOUT_SEC),
        _finite_timeout(dispatch_timeout, "dispatch timeout", MAX_DISPATCH_TIMEOUT_SEC),
        _finite_timeout(boot_timeout, "boot timeout", MAX_BOOT_TIMEOUT_SEC),
        _finite_timeout(poll_interval, "poll interval", MAX_POLL_INTERVAL_SEC),
    )


def _bridge_bindings_match(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Compare exact bridge identity while ignoring validation timestamp."""

    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def _require_transaction_capability(capability: object | None) -> None:
    if capability is not _TRANSACTION_CAPABILITY:
        raise RuntimeError(
            "direct native reboot mutation is disabled; use the durable collector"
        )


def _reject_symlink_components(path: Path, label: str = "path") -> None:
    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise RuntimeError(f"{label} component must not be a symlink: {cursor}")
        if cursor == anchor:
            return
        cursor = cursor.parent


def _atomic_json(path: Path, value: object) -> None:
    _reject_symlink_components(path.parent, "journal")
    data = json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError(f"journal temporary already exists; replay forbidden: {temporary}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
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


def _create_initial_json(path: Path, value: object) -> None:
    """Claim the final journal inode before bridge/stophud contact."""

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
                raise RuntimeError("short initial journal write")
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


def _reboot_effect_identity(boot_id: str) -> tuple[dict[str, object], str]:
    try:
        return native_transition_claim_identity(boot_id)
    except PhysicalClaimError as exc:
        raise ValueError(str(exc)) from exc


def _reboot_effect_claim_path(root: Path, key_sha256: str) -> Path:
    try:
        return native_transition_claim_path(Path(root), key_sha256)
    except PhysicalClaimError as exc:
        raise ValueError(str(exc)) from exc


def _create_reboot_effect_claim(
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
            provenance={"owner_kind": "native-reboot", "effect": "cmdv1 reboot"},
        )
    except PhysicalClaimAlreadyExists as exc:
        raise ValueError(
            "native reboot physical effect claim already exists; replay forbidden"
        ) from exc
    except PhysicalClaimError as exc:
        raise ValueError(str(exc)) from exc


def validate_reboot_transcript(transcript: bytes) -> dict[str, object]:
    """Validate the one exact CMD_NO_DONE reboot receipt.

    A reboot intentionally has no END frame.  The BEGIN record and reboot
    marker are therefore parsed as a pair, with exact command/sequence/
    argc/flags and duplicate/error END rejection.  Keeping this parser
    strict prevents a stale or spliced transcript from being accepted as the
    current boot's effect receipt.
    """

    if not isinstance(transcript, bytes):
        raise ValueError("reboot transcript is not bytes")
    if len(transcript) > MAX_DISPATCH_TRANSCRIPT_BYTES:
        raise ValueError("reboot transcript exceeds fixed bound")
    begins = list(REBOOT_BEGIN_RE.finditer(transcript))
    if len(begins) != 1:
        raise ValueError(f"reboot transcript has {len(begins)} BEGIN records")
    try:
        fields = parse_fields(begins[0].group("fields"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("reboot BEGIN fields are malformed") from exc
    if set(fields) != {"seq", "cmd", "argc", "flags"}:
        raise ValueError("reboot BEGIN fields are not the exact retained protocol")
    if fields.get("cmd") != "reboot":
        raise ValueError(f"reboot BEGIN command is not exact: {fields.get('cmd')!r}")
    sequence = fields.get("seq", "")
    if not sequence.isdigit() or (len(sequence) > 1 and sequence.startswith("0")):
        raise ValueError("reboot BEGIN sequence is malformed")
    if fields.get("argc") != EXPECTED_REBOOT_ARGC:
        raise ValueError(
            f"reboot BEGIN argc is not exact: {fields.get('argc')!r}"
        )
    if fields.get("flags") != EXPECTED_REBOOT_FLAGS:
        raise ValueError(
            f"reboot BEGIN flags are not exact CMD_NO_DONE 0x14: {fields.get('flags')!r}"
        )
    markers = list(REBOOT_MARKER_RE.finditer(transcript))
    if len(markers) != 1:
        raise ValueError(f"reboot transcript has {len(markers)} reboot markers")
    if REBOOT_ANY_END_RE.search(transcript) is not None:
        raise ValueError("reboot CMD_NO_DONE unexpectedly emitted an END frame")
    if begins[0].start() >= markers[0].start():
        raise ValueError("reboot marker appeared before the exact BEGIN record")
    return {
        "a90p1_begin_observed": True,
        "reboot_marker_observed": True,
        "begin": fields,
        "transcript_sha256": sha256(transcript),
        "transcript_size": len(transcript),
    }


def _dispatch_reboot_wire(
    host: str,
    port: int,
    timeout: float,
    *,
    capability: object | None = None,
) -> tuple[bytes, bool]:
    """Send the fixed reboot wire once and collect bounded receipt bytes."""

    _require_transaction_capability(capability)
    if host != "127.0.0.1" or port != 54321:
        raise ValueError("reboot dispatch accepts only the pinned 127.0.0.1:54321 bridge")
    timeout = _finite_timeout(timeout, "dispatch timeout", MAX_DISPATCH_TIMEOUT_SEC)
    data = bytearray()
    disconnected = False
    read_attempts = 0
    marker_seen = False
    try:
        sock = socket.create_connection(
            (host, port), timeout=min(timeout, DISPATCH_CONNECT_TIMEOUT_SEC)
        )
    except BaseException as exc:
        raise RuntimeError(f"reboot socket connect failed: {exc}") from exc
    try:
        try:
            sock.settimeout(min(DISPATCH_RECEIVE_TICK_SEC, timeout))
            sock.sendall(REBOOT_WIRE)
        except BaseException as exc:
            raise RuntimeError(f"reboot socket send failed: {exc}") from exc
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if read_attempts >= MAX_DISPATCH_READ_ATTEMPTS:
                raise RuntimeError("reboot socket receive attempt bound exceeded")
            read_attempts += 1
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError):
                disconnected = True
                break
            if not chunk:
                disconnected = True
                break
            if len(data) + len(chunk) > MAX_DISPATCH_TRANSCRIPT_BYTES:
                raise RuntimeError("reboot transcript exceeds fixed bound")
            data.extend(chunk)
            # Once the exact marker is present, the CMD_NO_DONE channel is
            # accepted.  Keep a short bounded teardown window so a duplicate
            # marker or forbidden END arriving in the same receipt is still
            # rejected by ``validate_reboot_transcript``; never wait for an
            # unbounded stream or require an END frame.
            if not marker_seen and REBOOT_MARKER_RE.search(data) is not None:
                marker_seen = True
                deadline = min(deadline, time.monotonic() + 3.0)
        if marker_seen:
            return bytes(data), disconnected
        raise RuntimeError(
            "reboot dispatch timed out before the exact acceptance marker"
        )
    finally:
        try:
            sock.close()
        except BaseException:
            pass


def dispatch_once(host: str, port: int, timeout: float) -> tuple[bytes, bool]:
    """Refuse the former unjournaled public mutation route."""

    del host, port, timeout
    raise RuntimeError(
        "direct native reboot mutation is disabled; use the durable collector"
    )


def _read(host: str, port: int, evidence_id: str, argv: tuple[str, ...], timeout: float) -> bytes:
    timeout = _finite_timeout(timeout, "command timeout", MAX_COMMAND_TIMEOUT_SEC)
    return exchange(host, port, Command(evidence_id, argv), timeout).payload


def _read_availability_frame(
    host: str, port: int, evidence_id: str, argv: tuple[str, ...], timeout: float
) -> object:
    """Read one availability frame while preserving exact busy semantics."""

    timeout = _finite_timeout(timeout, "availability timeout", MAX_COMMAND_TIMEOUT_SEC)
    # Busy is a complete, not-executed frame.  It must be visible to the
    # caller instead of being collapsed into the generic transport poll path.
    frame = exchange(
        host,
        port,
        Command(evidence_id, argv),
        timeout,
        allow_error=True,
    )
    begin = getattr(frame, "begin", {})
    end = getattr(frame, "end", {})
    if (
        not isinstance(begin, Mapping)
        or not isinstance(end, Mapping)
        or begin.get("cmd") != argv[0]
        or end.get("cmd") != argv[0]
        or begin.get("seq") != end.get("seq")
    ):
        raise AvailabilityFrameError(
            f"{evidence_id} frame command/sequence does not match fixed argv"
        )
    try:
        rc = int(end["rc"], 0)
        status = str(end["status"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AvailabilityFrameError(
            f"{evidence_id} frame lacks exact rc/status"
        ) from exc
    if rc == 0 and status == "ok":
        return frame
    if rc == -16 and status == "busy":
        raise AvailabilityBusy(f"{evidence_id} returned exact busy refusal")
    raise AvailabilityFrameError(
        f"{evidence_id} returned nonbusy error: rc={rc} status={status!r}"
    )


def _parse_boot_id(payload: bytes, label: str) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise AvailabilityFrameError(f"{label} is not ASCII") from exc
    # A boot ID is an exact UUID, not merely 36 lowercase hex/hyphen
    # characters.  The stricter shape prevents a malformed/spliced value from
    # being accepted as a new boot epoch.
    if BOOT_ID_RE.fullmatch(value) is None:
        raise AvailabilityFrameError(f"{label} is malformed")
    return value


def _preflight(host: str, port: int, timeout: float) -> dict[str, object]:
    version = _read(host, port, "version_before", ("version",), timeout)
    cmdline_raw = _read(host, port, "cmdline_before", ("cat", "/proc/cmdline"), timeout)
    cmdline = parse_cmdline(cmdline_raw)
    validate_runtime(version, cmdline)
    boot_id = _read(
        host,
        port,
        "boot_id_before",
        ("cat", "/proc/sys/kernel/random/boot_id"),
        timeout,
    )
    boot_id = _parse_boot_id(boot_id, "pre-reboot boot_id")
    return {"version": version, "cmdline": cmdline, "boot_id": boot_id}


def wait_for_new_boot(
    host: str,
    port: int,
    old_boot_id: str,
    timeout: float,
    poll_interval: float,
    *,
    stophud_frames: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if host != "127.0.0.1" or port != 54321:
        raise ValueError("native reboot observation accepts only the pinned 127.0.0.1:54321 bridge")
    if not isinstance(old_boot_id, str) or BOOT_ID_RE.fullmatch(old_boot_id) is None:
        raise ValueError("pre-reboot boot_id is malformed")
    timeout = _finite_timeout(timeout, "boot timeout", MAX_BOOT_TIMEOUT_SEC)
    poll_interval = _finite_timeout(
        poll_interval,
        "poll interval",
        MAX_POLL_INTERVAL_SEC,
    )
    deadline = time.monotonic() + timeout
    last_error = "no observation"
    attempts = 0
    frames = stophud_frames if stophud_frames is not None else []
    stophud_events: list[dict[str, object]] = []
    known_boot_id: str | None = None

    def remaining_timeout(label: str) -> float:
        remaining = deadline - time.monotonic()
        if remaining < MIN_TIMEOUT_SEC:
            raise TimeoutError(f"{label} exceeded the fixed overall boot deadline")
        return min(8.0, remaining)

    def bounded_sleep(delay: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining >= MIN_TIMEOUT_SEC:
            time.sleep(min(float(delay), remaining))

    def stop_current_boot(boot_id: str | None, reason: str) -> dict[str, object]:
        """Arbitrate only the exact holder refusal; never hide ambiguity."""

        event: dict[str, object] = {
            "reason": reason,
            "boot_id": boot_id,
            "fresh_bindings": [],
        }
        stophud_events.append(event)
        try:
            # This binding is intentionally fresh after reboot.  The binding
            # captured before reboot is never reused as mutation authority.
            fresh_binding = validate_bridge_binding()
            if not isinstance(fresh_binding, Mapping):
                raise TimeoutError("fresh A90 bridge binding is not an object")
            fresh_bindings = event["fresh_bindings"]
            assert isinstance(fresh_bindings, list)
            fresh_bindings.append(dict(fresh_binding))
            attempt = 0

            def bound_exchange(
                bound_host: str,
                bound_port: int,
                command: object,
                command_timeout: float,
                **kwargs: object,
            ) -> object:
                nonlocal attempt
                if attempt:
                    current_binding = validate_bridge_binding()
                    if not isinstance(current_binding, Mapping):
                        raise TimeoutError("fresh A90 bridge binding is not an object")
                    if not _bridge_bindings_match(fresh_binding, current_binding):
                        raise TimeoutError(
                            "bridge binding drifted before stophud retry"
                        )
                    fresh_bindings.append(dict(current_binding))
                attempt += 1
                bounded = remaining_timeout("stophud arbitration")
                return exchange(
                    bound_host,
                    bound_port,
                    command,
                    min(float(command_timeout), bounded),
                    **kwargs,
                )

            def stophud_sleep(delay: float) -> None:
                bounded_sleep(delay)

            result = run_stophud(
                host,
                port,
                remaining_timeout("stophud arbitration"),
                bound_exchange,
                frame_records=frames,
                sleep_fn=stophud_sleep,
            )
            event["result"] = result
            event["fresh_binding_count"] = len(fresh_bindings)
            return result
        except BaseException as exc:
            event["error_type"] = type(exc).__name__
            event["error"] = str(exc)
            event["fresh_binding_count"] = len(event["fresh_bindings"])
            raise

    while deadline - time.monotonic() >= MIN_TIMEOUT_SEC:
        attempts += 1
        try:
            # Version is the first availability probe.  Do not stophud merely
            # because the old boot briefly answered after reboot dispatch.
            version_frame = _read_availability_frame(
                host,
                port,
                "version_after",
                ("version",),
                remaining_timeout("version availability"),
            )
            version = version_frame.payload
        except AvailabilityBusy:
            try:
                stop_current_boot(known_boot_id, "version_availability_busy")
            except Exception as exc:
                raise TimeoutError(
                    f"native boot stophud arbitration incomplete: {type(exc).__name__}: {exc}"
                ) from exc
            last_error = "version availability was busy; stophud accepted"
            bounded_sleep(poll_interval)
            continue
        except AvailabilityFrameError as exc:
            raise TimeoutError(f"native boot availability failed: {exc}") from exc
        except Exception as exc:  # Device/bridge is expected to disappear temporarily.
            last_error = f"{type(exc).__name__}: {exc}"
            bounded_sleep(poll_interval)
            continue

        try:
            boot_frame = _read_availability_frame(
                host,
                port,
                "boot_id_after",
                ("cat", "/proc/sys/kernel/random/boot_id"),
                remaining_timeout("boot-id availability"),
            )
            boot_id = _parse_boot_id(boot_frame.payload, "post-reboot boot_id")
        except AvailabilityBusy:
            try:
                stop_current_boot(known_boot_id, "boot_id_availability_busy")
            except Exception as exc:
                raise TimeoutError(
                    f"native boot stophud arbitration incomplete: {type(exc).__name__}: {exc}"
                ) from exc
            last_error = "boot_id availability was busy; stophud accepted"
            bounded_sleep(poll_interval)
            continue
        except AvailabilityFrameError as exc:
            raise TimeoutError(f"native boot availability failed: {exc}") from exc
        except Exception as exc:  # Device/bridge is expected to disappear temporarily.
            last_error = f"{type(exc).__name__}: {exc}"
            bounded_sleep(poll_interval)
            continue
        known_boot_id = boot_id
        if boot_id == old_boot_id:
            last_error = "bridge answered from the pre-reboot boot ID"
            bounded_sleep(poll_interval)
            continue

        # The first changed boot ID is only a candidate: stophud on that exact
        # new boot (even if an old boot was stopped earlier), then re-read
        # version+boot_id to prove the arbitration belongs to this boot.
        try:
            stophud = stop_current_boot(boot_id, "new_boot_candidate")
            confirmed_version_frame = _read_availability_frame(
                host,
                port,
                "version_after_stophud",
                ("version",),
                remaining_timeout("post-stophud version availability"),
            )
            confirmed_boot_frame = _read_availability_frame(
                host,
                port,
                "boot_id_after_stophud",
                ("cat", "/proc/sys/kernel/random/boot_id"),
                remaining_timeout("post-stophud boot-id availability"),
            )
            confirmed_boot_id = _parse_boot_id(
                confirmed_boot_frame.payload, "post-stophud boot_id"
            )
            confirmed_version = confirmed_version_frame.payload
        except AvailabilityBusy as exc:
            # The new-boot stop was already attempted and a second stop could
            # be from an unknown epoch.  Preserve the incident; do not replay.
            raise TimeoutError(
                f"new native boot availability remained busy after stophud: {exc}"
            ) from exc
        except AvailabilityFrameError as exc:
            raise TimeoutError(
                f"new native boot availability failed after stophud: {exc}"
            ) from exc
        except Exception as exc:
            raise TimeoutError(
                f"new native boot stophud arbitration incomplete: {type(exc).__name__}: {exc}"
            ) from exc
        if confirmed_boot_id != boot_id:
            raise TimeoutError(
                "new native boot changed during stophud arbitration; observation incomplete"
            )
        return {
            "version": confirmed_version,
            "boot_id": confirmed_boot_id,
            "attempts": attempts,
            "stophud": stophud,
            "stophud_events": stophud_events,
            "candidate_version": version,
            "candidate_boot_id": boot_id,
        }
    raise TimeoutError(f"new native boot not observed: {last_error}")


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if not getattr(args, "execute", False):
        raise ValueError("reboot requires explicit --execute")
    experiment_id = getattr(args, "experiment_id", None)
    if not isinstance(experiment_id, str) or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise ValueError("invalid experiment ID")
    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 54321)
    if host != "127.0.0.1" or port != 54321:
        raise ValueError("reboot observer only accepts the pinned 127.0.0.1:54321 bridge")
    # The output tree is part of this owner identity.  It is deliberately not
    # a parser option, and an embedding caller cannot inject a replacement
    # Namespace attribute to create a replay namespace.
    if hasattr(args, "output_root"):
        # The production parser has no output-root option.  Refuse an
        # embedding Namespace attribute altogether, including a spelling of
        # the fixed root, so this owner has one physical evidence namespace.
        raise ValueError(
            "output_root selector is disabled; reboot evidence is fixed under REPO_ROOT"
        )
    expect_debug_after = getattr(args, "expect_debug_after", None)
    if expect_debug_after not in DEBUG_CMDLINE:
        raise ValueError("expect-debug-after must be one of the fixed debug profiles")
    command_timeout, dispatch_timeout, boot_timeout, poll_interval = _validate_timeout_set(
        command_timeout=getattr(args, "command_timeout", DEFAULT_COMMAND_TIMEOUT_SEC),
        dispatch_timeout=getattr(args, "dispatch_timeout", DEFAULT_DISPATCH_TIMEOUT_SEC),
        boot_timeout=getattr(args, "boot_timeout", DEFAULT_BOOT_TIMEOUT_SEC),
        poll_interval=getattr(args, "poll_interval", DEFAULT_POLL_INTERVAL_SEC),
    )
    root_input = Path(REPO_ROOT)
    _reject_symlink_components(root_input, "output root")
    root = root_input.resolve(strict=False)
    journal_path = root / "evidence/private" / f"{experiment_id}.journal.json"
    manifest_path = root / "evidence/manifests" / f"{experiment_id}.manifest.json"
    _reject_symlink_components(journal_path, "journal")
    _reject_symlink_components(manifest_path, "manifest")
    for path in (journal_path, manifest_path):
        temporary = path.with_name(path.name + ".tmp")
        if path.exists() or path.is_symlink() or temporary.exists() or temporary.is_symlink():
            raise FileExistsError("reboot evidence exists; the effect is never replayed")
    journal_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(journal_path.parent, 0o700)
    os.chmod(manifest_path.parent, 0o755)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    pre_stophud_frames: list[dict[str, object]] = []
    journal: dict[str, object] = {
        "schema": "sdm855-a90-native-reboot-journal-v1",
        "experiment_id": experiment_id,
        "started_utc": started,
        "status": "STOPHUD_INTENT_DURABLE",
        "effect": "cmdv1 reboot",
        "effect_dispatched": False,
        "effect_replayed": False,
        "expected_debug_after": expect_debug_after,
        "pre_stophud": None,
        "pre_stophud_frames": pre_stophud_frames,
        "physical_effect_claim": {
            "claimed": False,
            "attempted": False,
            "key_sha256": None,
            "claim_path": None,
            "claim_sha256": None,
            "claim_size": None,
            "boot_id": None,
        },
    }
    _create_initial_json(journal_path, journal)
    effect_claim_identity: dict[str, object] | None = None
    effect_claim_key_sha256: str | None = None
    effect_claim_path: Path | None = None
    effect_claim_data: bytes | None = None
    effect_claim_attempted = False
    effect_claimed = False

    def persist_pre_stophud(attempts: list[dict[str, object]]) -> None:
        journal["pre_stophud_attempts"] = attempts
        journal["pre_stophud_frames"] = pre_stophud_frames
        _atomic_json(journal_path, journal)

    bridge_binding: Mapping[str, object] | None = None
    try:
        # The first stateful command is allowed only after the exact local
        # A90 bridge/serial identity has been bound and durably recorded.
        bridge_binding = validate_bridge_binding()
        if not isinstance(bridge_binding, Mapping):
            raise ValueError("initial bridge binding is not an object")
        journal["bridge_binding"] = dict(bridge_binding)
        _atomic_json(journal_path, journal)

        def bound_stophud_exchange(
            bound_host: str,
            bound_port: int,
            command: object,
            command_timeout: float,
            **kwargs: object,
        ) -> object:
            # Re-bind immediately before each stophud attempt, including a
            # retry following a complete busy refusal.  A bridge drift before
            # attempt two therefore yields an incident and no second effect.
            current_binding = validate_bridge_binding()
            if not isinstance(current_binding, Mapping) or not _bridge_bindings_match(
                bridge_binding,
                current_binding,
            ):
                raise RuntimeError("bridge binding drifted before stophud attempt")
            return exchange(
                bound_host,
                bound_port,
                command,
                command_timeout,
                **kwargs,
            )

        # stophud is the first device command.  Its durable pre-effect record
        # retains busy refusals and any transport incident before preflight.
        pre_stophud = run_stophud(
            host,
            port,
            command_timeout,
            bound_stophud_exchange,
            frame_records=pre_stophud_frames,
            persist=persist_pre_stophud,
        )
        journal["pre_stophud"] = pre_stophud
        before = _preflight(host, port, command_timeout)
        current_debug = before["cmdline"].get("androidboot.debug_level")
        expected_predecessor_debug = DEBUG_CMDLINE[
            EXPECTED_DEBUG_PREDECESSOR[expect_debug_after]
        ]
        if current_debug != expected_predecessor_debug:
            raise ValueError(
                "requested reboot debug profile does not follow the exact current predecessor"
            )
    except BaseException as exc:
        journal["status"] = "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
        journal["error"] = f"{type(exc).__name__}: {exc}"
        journal["pre_stophud_frames"] = pre_stophud_frames
        _atomic_json(journal_path, journal)
        raise

    journal.update(
        {
            "status": "INTENT_DURABLE_PRE_EFFECT",
            "before": {
                "boot_id": before["boot_id"],
                "cmdline": before["cmdline"],
                "version_base64": base64.b64encode(before["version"]).decode("ascii"),
            },
            "pre_stophud": pre_stophud,
            "pre_stophud_frames": pre_stophud_frames,
        }
    )
    try:
        if bridge_binding is None:
            raise RuntimeError("reboot arm lacks initial bridge binding")
        final_bridge_binding = revalidate_bridge_binding(bridge_binding)
        if not isinstance(final_bridge_binding, Mapping) or not _bridge_bindings_match(
            bridge_binding, final_bridge_binding
        ):
            raise RuntimeError("bridge binding drifted before reboot arm")
        boot_id = str(before["boot_id"])
        effect_claim_identity, effect_claim_key_sha256 = _reboot_effect_identity(boot_id)
        effect_claim_path = _reboot_effect_claim_path(root, effect_claim_key_sha256)
        claim_boot_id = _parse_boot_id(
            _read(
                host,
                port,
                "boot_id_claim",
                ("cat", "/proc/sys/kernel/random/boot_id"),
                command_timeout,
            ),
            "pre-reboot claim boot_id",
        )
        if claim_boot_id != boot_id:
            raise RuntimeError("native reboot boot_id changed before effect claim")
        try:
            existing_claim = inspect_native_transition_claim(root, claim_boot_id)
        except PhysicalClaimPartial as exc:
            raise RuntimeError(str(exc)) from exc
        if existing_claim is not None:
            raise RuntimeError(
                "native reboot physical effect claim already exists; replay forbidden"
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
                    "owner_kind": "native-reboot",
                    "effect": "cmdv1 reboot",
                    "expect_debug_after": expect_debug_after,
                },
            )
        except PhysicalClaimAlreadyExists as exc:
            raise RuntimeError(
                "native reboot physical effect claim already exists; replay forbidden"
            ) from exc
        except PhysicalClaimError as exc:
            raise RuntimeError(str(exc)) from exc
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
    except BaseException as exc:
        journal["status"] = (
            "PHYSICAL_EFFECT_CLAIMED_RECONCILIATION_REQUIRED"
            if effect_claim_attempted
            else "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
        )
        journal["error"] = f"{type(exc).__name__}: {exc}"
        physical = journal.get("physical_effect_claim")
        if isinstance(physical, dict):
            physical["claimed"] = effect_claimed or bool(
                effect_claim_path and effect_claim_path.exists()
            )
        _atomic_json(journal_path, journal)
        raise
    journal["pre_effect_bridge_binding"] = dict(final_bridge_binding)
    _atomic_json(journal_path, journal)

    journal["effect_dispatched"] = True
    journal["status"] = "EFFECT_DISPATCH_STARTED"
    _atomic_json(journal_path, journal)
    post_stophud_frames: list[dict[str, object]] = []

    def dispatch_transaction() -> tuple[bytes, bool]:
        return _dispatch_reboot_wire(
            host,
            port,
            dispatch_timeout,
            capability=_TRANSACTION_CAPABILITY,
        )

    try:
        # A fresh binding is required after the durable marker and immediately
        # before the sole reboot effect.  Do not fsync or issue another device
        # command between this bind and dispatch; retain it only after the
        # effect returns (or conservatively omit it on an ambiguous failure).
        post_marker_binding = revalidate_bridge_binding(final_bridge_binding)
        if not isinstance(post_marker_binding, Mapping) or not _bridge_bindings_match(
            final_bridge_binding, post_marker_binding
        ):
            raise RuntimeError("bridge binding drifted after reboot marker")
        transcript, disconnected = dispatch_transaction()
        receipt = validate_reboot_transcript(transcript)
        receipt["socket_disconnect_observed"] = disconnected
        receipt["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
        journal["post_marker_bridge_binding"] = dict(post_marker_binding)
        journal["dispatch_receipt"] = receipt
        journal["status"] = "EFFECT_ACCEPTED_WAITING_FOR_NEW_BOOT"
        _atomic_json(journal_path, journal)

        after = wait_for_new_boot(
            host,
            port,
            str(before["boot_id"]),
            boot_timeout,
            poll_interval,
            stophud_frames=post_stophud_frames,
        )
        cmdline_raw = _read(
            host, port, "cmdline_after", ("cat", "/proc/cmdline"), command_timeout
        )
        cmdline = parse_cmdline(cmdline_raw)
        validate_runtime(after["version"], cmdline)
        expected_debug = DEBUG_CMDLINE[expect_debug_after]
        if cmdline.get("androidboot.debug_level") != expected_debug:
            raise ValueError(
                f"post-reboot debug level {cmdline.get('androidboot.debug_level')!r} "
                f"!= {expected_debug!r}"
            )
        if cmdline.get("androidboot.force_upload") != "0x0":
            raise ValueError("post-reboot force_upload is not zero")
        if cmdline.get("sec_debug.dump_sink") != "0x0":
            raise ValueError("post-reboot dump_sink is not USB default")
        dload = _read(
            host,
            port,
            "download_mode_after",
            ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
            command_timeout,
        ).decode("ascii", errors="strict").strip()
        if dload != "1":
            raise ValueError("post-reboot download_mode is not 1")
        selftest_payload = _read(
            host, port, "selftest_after", ("selftest", "status"), command_timeout
        )
        selftest = parse_selftest(selftest_payload)
        # Re-read the boot ID after all post-boot evidence.  A single receipt
        # must not splice cmdline/download/selftest from one boot with a boot
        # ID from another epoch.
        final_boot_id = _parse_boot_id(
            _read(
                host,
                port,
                "boot_id_final",
                ("cat", "/proc/sys/kernel/random/boot_id"),
                command_timeout,
            ),
            "final post-reboot boot_id",
        )
        journal["final_boot_id_observed"] = final_boot_id
        if final_boot_id != after["boot_id"]:
            raise ValueError(
                "post-reboot boot_id changed while collecting final health evidence"
            )
        journal["after"] = {
            "boot_id": after["boot_id"],
            "boot_id_final": final_boot_id,
            "poll_attempts": after["attempts"],
            "cmdline": cmdline,
            "download_mode": dload,
            "selftest": selftest,
            "stophud": after["stophud"],
            "stophud_frames": post_stophud_frames,
            "stophud_events": after.get("stophud_events", []),
            "candidate_boot_id": after["candidate_boot_id"],
        }
        journal["completed_utc"] = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat()
        journal["status"] = "NEW_BOOT_PROVED"
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        journal["status"] = "EFFECT_DISPATCHED_OBSERVATION_INCOMPLETE"
        journal["error"] = f"{type(exc).__name__}: {exc}"
        journal["post_stophud_frames"] = post_stophud_frames
        _atomic_json(journal_path, journal)
        raise

    manifest = {
        "schema": "sdm855-a90-native-reboot-public-v1",
        "experiment_id": experiment_id,
        "started_utc": started,
        "completed_utc": journal["completed_utc"],
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
        "classification": journal["status"],
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "cmd_no_done": True,
        "dispatch_receipt": {
            key: value
            for key, value in journal["dispatch_receipt"].items()
            if key != "transcript_base64"
        },
        "physical_effect_claim": {
            key: journal.get("physical_effect_claim", {}).get(key)
            for key in (
                "claimed",
                "attempted",
                "key_sha256",
                "claim_sha256",
                "claim_size",
                "boot_id",
            )
            if isinstance(journal.get("physical_effect_claim"), Mapping)
            and key in journal.get("physical_effect_claim", {})
        },
        "pre_stophud_accepted": journal["pre_stophud"]["accepted"],
        "pre_stophud_busy_retries": journal["pre_stophud"]["busy_retries"],
        "boot_id_changed": journal["before"]["boot_id"] != journal["after"]["boot_id"],
        "post_boot": {
            "debug_level": journal["after"]["cmdline"].get("androidboot.debug_level"),
            "force_upload": journal["after"]["cmdline"].get("androidboot.force_upload"),
            "dump_sink": journal["after"]["cmdline"].get("sec_debug.dump_sink"),
            "download_mode": journal["after"]["download_mode"],
            "selftest": journal["after"]["selftest"],
            "stophud_accepted": journal["after"]["stophud"]["accepted"],
            "stophud_busy_retries": journal["after"]["stophud"]["busy_retries"],
        },
        "claims": {
            "PROVED": [
                "The reboot command was dispatched exactly once and accepted by the exact A90P1 CMD_NO_DONE path.",
                "A different boot ID returned with the exact native runtime and requested source-backed debug-level cmdline value.",
            ]
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return journal_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--expect-debug-after", required=True, choices=tuple(DEBUG_CMDLINE))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--command-timeout", type=float, default=15.0)
    parser.add_argument("--dispatch-timeout", type=float, default=10.0)
    parser.add_argument("--boot-timeout", type=float, default=240.0)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    journal, manifest = collect(args)
    print(f"journal: {journal}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
