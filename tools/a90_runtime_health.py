#!/usr/bin/env python3
"""Capture the exact final-rollback A90 native runtime-health receipt.

The V024 lifecycle uses this observer after a returned control operation or a
rollback.  It speaks only through the repository's local partial-evidence-
preserving A90P1 transport, binds the exact operator-owned A90 bridge, and
  uses the shared bounded ``stophud`` arbitration before the first device
  command.  The current-boot prefix proof also performs bounded temporary
  filesystem/block-node mutations (mkdir, mknodb, dd-to-temp, and cleanup);
  these are recorded explicitly and are not described as read-only.  No
  partition, MMIO, controller, security-state, or persistent write is
  performed.  Full frames remain private and the public manifest contains
  only bounded, redacted fields.

This observer is intentionally a final-rollback gate: it hard-pins the
currently running 60,882,944-byte boot prefix to the rollback candidate
``ca978...``.  The control candidate's same-boot health belongs to the MID
probe and is not interchangeable with this receipt.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import math
import os
import re
import stat
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import Command, Frame, json_bytes, write_new
    from tools.a90_autohud_arbitration import run_stophud
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
        exchange as native_exchange,
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    from tools.a90_v024_boot_attestation import (
        BOOT_ATTEST_FILE,
        BOOT_PREFIX_SIZE,
        V024_NATIVE_TEMP_PATHS,
        attest_current_boot,
        verify_v024_temp_absence,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, Frame, json_bytes, write_new  # type: ignore
    from a90_autohud_arbitration import run_stophud  # type: ignore
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
        exchange as native_exchange,
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    from a90_v024_boot_attestation import (  # type: ignore
        BOOT_ATTEST_FILE,
        BOOT_PREFIX_SIZE,
        V024_NATIVE_TEMP_PATHS,
        attest_current_boot,
        verify_v024_temp_absence,
    )


exchange = native_exchange
REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_HEALTH_EXPERIMENT_ID = "runtime-health"
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
MAX_TIMEOUT_SEC = 120.0
ROLLBACK_BOOT_SHA256 = (
    "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb"
)
LOCAL_TRANSPORT_MODULE = "tools.a90_pa28_live"
LOCAL_TRANSPORT_SOURCE = "tools/a90_pa28_live.py"
CMDLINE_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]+\Z")
KNOWN_BARE_FLAGS = frozenset({"skip_initramfs", "rootwait", "ro"})
VERSION_RE = re.compile(
    r"version: (?P<version>[^\r\n ]+) build=(?P<build>[^\r\n ]+)\Z"
)
SELFTEST_RE = re.compile(
    r"selftest: pass=(?P<passed>[0-9]+) warn=(?P<warn>[0-9]+) "
    r"fail=(?P<fail>[0-9]+) duration=(?P<duration>[0-9]+)ms "
    r"entries=(?P<entries>[0-9]+)\Z"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_file_bytes(path: Path) -> bytes:
    """Read one private receipt through a stable no-follow descriptor."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical.parent
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise ValueError(f"private receipt parent is a symlink: {cursor}")
        if cursor == anchor:
            break
        cursor = cursor.parent
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"private receipt cannot be opened: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"private receipt is not regular: {path}")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or len(data) != after.st_size:
            raise ValueError(f"private receipt changed while being read: {path}")
        return bytes(data)
    finally:
        os.close(descriptor)


def parse_version(payload: bytes) -> dict[str, str]:
    """Parse exactly one version/build line."""

    try:
        text = payload.decode("ascii", errors="strict").replace("\r", "").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("version payload is not ASCII") from exc
    matches = [VERSION_RE.fullmatch(line) for line in text.splitlines() if line.strip()]
    matches = [match for match in matches if match is not None]
    if len(matches) != 1:
        raise ValueError("version payload lacks exact version/build line")
    return {key: value for key, value in matches[0].groupdict().items()}


def parse_cmdline(payload: bytes) -> dict[str, str]:
    """Parse every cmdline token and reject malformed/duplicate keys."""

    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("cmdline payload is not ASCII") from exc
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
        raise ValueError("cmdline framing is not exact")
    if any(char.isspace() and char != " " for char in text):
        raise ValueError("cmdline contains non-space whitespace")
    result: dict[str, str] = {}
    for token in (item for item in text.split(" ") if item):
        if "=" not in token:
            if token not in KNOWN_BARE_FLAGS:
                raise ValueError(f"malformed cmdline token: {token!r}")
            if token in result:
                raise ValueError(f"duplicate cmdline key: {token}")
            result[token] = ""
            continue
        key, value = token.split("=", 1)
        if (
            CMDLINE_KEY_RE.fullmatch(key) is None
            or not value
            or any(ord(char) < 0x21 or ord(char) == 0x7F for char in value)
        ):
            raise ValueError(f"malformed cmdline key/value: {token!r}")
        if key in result:
            raise ValueError(f"duplicate cmdline key: {key}")
        result[key] = value
    return result


def parse_selftest(payload: bytes) -> dict[str, int]:
    """Require the exact V024 selftest summary 11/1/0/12."""

    try:
        text = payload.decode("ascii", errors="strict").replace("\r", "").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("selftest payload is not ASCII") from exc
    matches = [SELFTEST_RE.fullmatch(line) for line in text.splitlines() if line.strip()]
    matches = [match for match in matches if match is not None]
    if len(matches) != 1:
        raise ValueError("selftest payload lacks exact summary")
    result = {key: int(value) for key, value in matches[0].groupdict().items()}
    if (
        result["passed"] != 11
        or result["warn"] != 1
        or result["fail"] != 0
        or result["entries"] != 12
    ):
        if result["fail"] != 0:
            raise ValueError("runtime selftest reports failures")
        raise ValueError(f"runtime selftest is not exact 11/1/0/12: {result}")
    if result["duration"] < 0 or result["duration"] > 120_000:
        raise ValueError("runtime selftest duration is outside the bounded range")
    return result


def parse_battery(payload: bytes) -> int:
    try:
        text = payload.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("battery payload is not ASCII") from exc
    if not re.fullmatch(r"[0-9]+", text) or not 0 <= int(text, 10) <= 100:
        raise ValueError("battery capacity is not a bounded decimal percentage")
    return int(text, 10)


def validate_target(
    version_payload: bytes,
    cmdline_payload: bytes,
    soc_payload: bytes,
    panic_payload: bytes,
) -> tuple[dict[str, str], dict[str, str], int, int]:
    """Require exact V2321/SM-A908N/SM8150 LOW and panic=1 state."""

    try:
        version_text = version_payload.decode("ascii", errors="strict").replace("\r", "")
    except UnicodeDecodeError as exc:
        raise ValueError("version payload is not ASCII") from exc
    lines = [line.strip() for line in version_text.splitlines() if line.strip()]
    expected_lines = (
        f"{EXPECTED_VERSION} ({EXPECTED_RUNTIME_BUILD})",
        f"version: {EXPECTED_RUNTIME} {EXPECTED_BUILD}",
        f"kernel: {EXPECTED_KERNEL}",
    )
    prefixes = ("A90 Linux init ", "version: ", "kernel: ")
    for prefix, expected in zip(prefixes, expected_lines):
        matching = [line for line in lines if line.startswith(prefix)]
        if matching != [expected]:
            raise ValueError("live version is not the exact V2321 runtime")

    cmdline = parse_cmdline(cmdline_payload)
    expected_cmdline = {
        "androidboot.em.model": EXPECTED_MODEL,
        "androidboot.bootloader": EXPECTED_BOOTLOADER,
        "androidboot.debug_level": "0x4f4c",
    }
    for key, expected in expected_cmdline.items():
        if cmdline.get(key) != expected:
            raise ValueError(f"live cmdline is not exact for {key}")
    if cmdline.get("androidboot.force_upload") not in {"0", "0x0"}:
        raise ValueError("live cmdline force_upload is not zero")
    if cmdline.get("sec_debug.dump_sink") not in {"0", "0x0"}:
        raise ValueError("live cmdline dump_sink is not zero")

    def one_line(payload: bytes, label: str) -> str:
        try:
            value = payload.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise ValueError(f"{label} is not ASCII") from exc
        if not value or "\n" in value or "\r" in value or "\x00" in value:
            raise ValueError(f"{label} is not one bounded value")
        return value

    soc_id = one_line(soc_payload, "soc_id")
    if soc_id != "339":
        raise ValueError(f"live soc_id is not SM8150/339: {soc_id!r}")
    panic = one_line(panic_payload, "panic_on_oops")
    if panic != "1":
        raise ValueError(f"panic_on_oops is not exact 1: {panic!r}")
    version = parse_version(version_payload)
    return version, cmdline, int(soc_id, 10), int(panic, 10)


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


def _atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    data = json_bytes(value)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(f"private journal temporary already exists: {temporary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _exclusive_json(path: Path, value: object, mode: int = 0o600) -> None:
    """Create the initial journal at its final inode with O_EXCL."""

    data = json_bytes(value)
    _reject_symlink_components(path.parent, "initial private journal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    # Never unlink a partially created final journal: its inode is the
    # durable no-replay ownership claim for this fixed experiment.
    descriptor = os.open(path, flags, mode)
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
        raise


def _reject_existing(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"output already exists: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(f"output temporary already exists: {temporary}")


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
    for item in (
        resolved,
        resolved / "evidence",
        resolved / "evidence/private",
        resolved / "evidence/manifests",
    ):
        if item.is_symlink():
            raise ValueError(f"evidence path component must not be a symlink: {item}")
    return resolved


def _fixed_output_root(args: argparse.Namespace) -> Path:
    """Use only the repository-owned evidence namespace.

    The production CLI deliberately has no output-root selector.  Keep an
    explicit Namespace check because callers can still construct one by
    hand; a non-fixed namespace must be rejected before bridge validation or
    any device contact.  Tests patch ``REPO_ROOT`` to an isolated fixture.
    """

    _validate_output_root(REPO_ROOT)
    expected = REPO_ROOT.resolve()
    # Apply the no-symlink evidence-root check to the default path as well as
    # an injected test selector, before any journal or bridge work occurs.
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


def _public_record(record: Mapping[str, object]) -> dict[str, object]:
    return {
        key: record[key]
        for key in (
            "evidence_id",
            "argv",
            "end",
            "payload_sha256",
            "payload_size",
            "transcript_sha256",
            "transcript_size",
        )
        if key in record
    }


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if not getattr(args, "execute", False):
        raise ValueError("runtime health requires explicit --execute")
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    if args.experiment_id != RUNTIME_HEALTH_EXPERIMENT_ID:
        raise ValueError("runtime health experiment ID is fixed to runtime-health")
    if args.host != BRIDGE_HOST or args.port != BRIDGE_PORT:
        raise ValueError("health observer accepts only the exact loopback A90 bridge")
    if (
        not isinstance(args.timeout, (int, float))
        or isinstance(args.timeout, bool)
        or not math.isfinite(float(args.timeout))
        or not 0 < float(args.timeout) <= MAX_TIMEOUT_SEC
    ):
        raise ValueError(f"timeout must be within 0 < timeout <= {MAX_TIMEOUT_SEC:g}")

    # Resolve the fixed root before creating journals or contacting the
    # bridge.  ``output_root`` is accepted only as an equal-value test seam.
    root = _fixed_output_root(args)
    private_root = root / "evidence/private"
    manifest_root = root / "evidence/manifests"
    private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest_root.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(private_root, 0o700)
    os.chmod(manifest_root, 0o755)
    raw_path = private_root / f"{args.experiment_id}.json"
    journal_path = private_root / f"{args.experiment_id}.journal.json"
    manifest_path = manifest_root / f"{args.experiment_id}.manifest.json"
    for path in (raw_path, journal_path, manifest_path):
        _reject_existing(path)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    records: list[dict[str, object]] = []
    stophud_frames: list[dict[str, object]] = []
    # The shared arbiter deliberately keeps only redacted provenance.  Retain
    # the corresponding in-memory frames here so the private final receipt can
    # bind both payload and transcript bytes without exposing them publicly.
    stophud_frame_objects: dict[str, object] = {}
    attestation_frame_objects: dict[str, object] = {}
    journal: dict[str, object] = {
        "schema": "sdm855-a90-runtime-health-private-v2",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "status": "STOPHUD_INTENT_DURABLE",
        "effect_dispatched": False,
        "effect_replayed": False,
        "transport_module": LOCAL_TRANSPORT_MODULE,
        "transport_source": LOCAL_TRANSPORT_SOURCE,
        "stophud": None,
        "stophud_frames": stophud_frames,
        "boot_attestation": None,
        "v024_temp_absence": None,
        "records": records,
    }
    _exclusive_json(journal_path, journal)

    def persist_stophud(attempts: list[dict[str, object]]) -> None:
        for item in stophud_frames:
            evidence_id = item.get("evidence_id")
            frame = stophud_frame_objects.get(str(evidence_id))
            if frame is None:
                continue
            payload = getattr(frame, "payload", None)
            transcript = getattr(frame, "transcript", None)
            if not isinstance(payload, bytes) or not isinstance(transcript, bytes):
                continue
            item.update(
                {
                    "payload_base64": base64.b64encode(payload).decode("ascii"),
                    "payload_sha256": sha256(payload),
                    "payload_size": len(payload),
                    "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                    "transcript_sha256": sha256(transcript),
                    "transcript_size": len(transcript),
                    "begin": dict(getattr(frame, "begin", {})),
                    "end": dict(getattr(frame, "end", {})),
                }
            )
        journal["stophud_attempts"] = attempts
        journal["stophud_frames"] = stophud_frames
        _atomic_json(journal_path, journal)

    def exchange_once(command: Command) -> Frame:
        try:
            frame = exchange(args.host, args.port, command, args.timeout)
        except BaseException as exc:
            record = _partial_record(command, exc)
            records.append(record)
            journal["records"] = records
            journal["status"] = "INCIDENT"
            journal["error"] = f"{type(exc).__name__}: {exc}"
            _atomic_json(journal_path, journal)
            raise
        begin = getattr(frame, "begin", None)
        end = getattr(frame, "end", None)
        if (
            not isinstance(begin, Mapping)
            or not isinstance(end, Mapping)
            or begin.get("cmd") != command.argv[0]
            or end.get("cmd") != command.argv[0]
            or begin.get("seq") != end.get("seq")
        ):
            error = ValueError(
                f"{command.evidence_id} frame command/sequence does not match fixed argv"
            )
            records.append(_partial_record(command, error))
            journal["records"] = records
            journal["status"] = "INCIDENT"
            journal["error"] = str(error)
            _atomic_json(journal_path, journal)
            raise error
        record = _frame_record(command, frame)
        records.append(record)
        journal["records"] = records
        _atomic_json(journal_path, journal)
        # A transport frame is only a successful exchange when its terminal
        # record carries the exact successful rc/status pair.  Retain the
        # complete frame first, then durably classify a non-success terminal
        # as an incident; it must never flow into a PASS receipt.
        try:
            if not isinstance(end, Mapping):
                raise TypeError("frame END is not an object")
            rc = int(end.get("rc"), 0)
        except (TypeError, ValueError) as exc:
            error = ValueError(
                f"{command.evidence_id} frame rc is malformed"
            )
            journal["status"] = "INCIDENT"
            journal["error"] = str(error)
            _atomic_json(journal_path, journal)
            raise error from exc
        if rc != 0 or end.get("status") != "ok":
            error = ValueError(
                f"{command.evidence_id} frame did not complete successfully"
            )
            journal["status"] = "INCIDENT"
            journal["error"] = str(error)
            _atomic_json(journal_path, journal)
            raise error
        return frame

    def attestation_exchange(
        host: str, port: int, command: Command, timeout: float
    ) -> Frame:
        """Adapt the shared attestation callback to the journaling exchange."""

        del host, port, timeout
        frame = exchange_once(command)
        attestation_frame_objects[command.evidence_id] = frame
        return frame

    def complete_attestation_frames(frames: list[dict[str, object]]) -> None:
        for item in frames:
            evidence_id = item.get("evidence_id")
            frame = attestation_frame_objects.get(str(evidence_id))
            if frame is None:
                continue
            payload = getattr(frame, "payload", None)
            transcript = getattr(frame, "transcript", None)
            if not isinstance(payload, bytes) or not isinstance(transcript, bytes):
                continue
            item.update(
                {
                    "payload_base64": base64.b64encode(payload).decode("ascii"),
                    "payload_sha256": sha256(payload),
                    "payload_size": len(payload),
                    "transcript_base64": base64.b64encode(transcript).decode("ascii"),
                    "transcript_sha256": sha256(transcript),
                    "transcript_size": len(transcript),
                    "begin": dict(getattr(frame, "begin", {})),
                    "end": dict(getattr(frame, "end", {})),
                }
            )

    try:
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
            # The shared arbiter calls this immediately before every attempt,
            # including busy retries.  No substantive command may follow a
            # stale bridge identity.
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
            # run_stophud assigns the next stable evidence ID immediately
            # after this callback returns.  Capture that mapping before its
            # persist callback so private stophud frames can carry the same
            # complete payload/transcript binding as other exchanges.
            stophud_frame_objects[f"stophud_{len(stophud_frames) + 1}"] = frame
            return frame

        stophud = run_stophud(
            args.host,
            args.port,
            args.timeout,
            guarded_stophud_exchange,
            frame_records=stophud_frames,
            persist=persist_stophud,
        )
        # The accepted attempt is appended by run_stophud immediately before
        # its final persist callback.  Refresh once more for a defensive
        # binding if a compatible arbiter changes callback ordering.
        persist_stophud(list(stophud.get("attempts", [])))
        journal["stophud"] = stophud
        journal["stophud_frames"] = stophud_frames
        journal["status"] = "PREFLIGHT"
        journal["bridge_binding"] = bridge_binding
        _atomic_json(journal_path, journal)
        post_stophud_binding = revalidate_bridge_binding(bridge_binding)
        if not isinstance(post_stophud_binding, Mapping) or not _bridge_bindings_match(
            bridge_binding, post_stophud_binding
        ):
            raise ValueError("bridge binding drifted after stophud")
        journal["post_stophud_bridge_binding"] = post_stophud_binding
        _atomic_json(journal_path, journal)

        version_frame = exchange_once(Command("version", ("version",)))
        cmdline_frame = exchange_once(
            Command("cmdline", ("cat", "/proc/cmdline"))
        )
        soc_frame = exchange_once(
            Command("soc_id", ("cat", "/sys/devices/soc0/soc_id"))
        )
        panic_frame = exchange_once(
            Command("panic_on_oops", ("cat", "/proc/sys/kernel/panic_on_oops"))
        )
        version, cmdline, soc_id, panic = validate_target(
            version_frame.payload,
            cmdline_frame.payload,
            soc_frame.payload,
            panic_frame.payload,
        )
        boot_attestation_frames: list[dict[str, object]] = []
        boot_attestation = attest_current_boot(
            args.host,
            args.port,
            args.timeout,
            ROLLBACK_BOOT_SHA256,
            boot_attestation_frames,
            bridge_binding=post_stophud_binding,
            exchange_fn=attestation_exchange,
            revalidate_fn=revalidate_bridge_binding,
        )
        temp_absence_frames: list[dict[str, object]] = []
        v024_temp_absence = verify_v024_temp_absence(
            args.host,
            args.port,
            args.timeout,
            temp_absence_frames,
            exchange_fn=attestation_exchange,
        )
        v024_temp_absence.update(
            {
                "paths_count": len(V024_NATIVE_TEMP_PATHS),
                "paths_sha256": sha256(json_bytes(list(V024_NATIVE_TEMP_PATHS))),
            }
        )
        complete_attestation_frames(boot_attestation_frames)
        complete_attestation_frames(temp_absence_frames)
        journal["boot_attestation"] = {
            **boot_attestation,
            "frames": boot_attestation_frames,
        }
        journal["v024_temp_absence"] = {
            **v024_temp_absence,
            "frames": temp_absence_frames,
        }
        _atomic_json(journal_path, journal)
        selftest_frame = exchange_once(Command("selftest", ("selftest", "status")))
        battery_frame = exchange_once(
            Command("battery_capacity", ("cat", "/sys/class/power_supply/battery/capacity"))
        )
        selftest = parse_selftest(selftest_frame.payload)
        battery = parse_battery(battery_frame.payload)
        final_binding = revalidate_bridge_binding(post_stophud_binding)
        if not isinstance(final_binding, Mapping) or not _bridge_bindings_match(
            post_stophud_binding, final_binding
        ):
            raise ValueError("bridge binding drifted before runtime-health publication")
        journal["final_bridge_binding"] = final_binding
        completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        raw = {
            "schema": "sdm855-a90-runtime-health-private-v2",
            "health_scope": "FINAL_ROLLBACK_ONLY",
            "experiment_id": args.experiment_id,
            "started_utc": started,
            "completed_utc": completed,
            "transport_module": LOCAL_TRANSPORT_MODULE,
            "transport_source": LOCAL_TRANSPORT_SOURCE,
            "target": {
                "model": EXPECTED_MODEL,
                "soc": EXPECTED_SOC,
                "runtime": EXPECTED_RUNTIME,
                "version": version,
                "kernel": EXPECTED_KERNEL,
                "bootloader": EXPECTED_BOOTLOADER,
                "cmdline": cmdline,
                "soc_id": soc_id,
                "panic_on_oops": panic,
            },
            "bridge_binding": bridge_binding,
            "post_stophud_bridge_binding": post_stophud_binding,
            "final_bridge_binding": final_binding,
            "stophud": stophud,
            "stophud_frames": stophud_frames,
            "records": records,
            "boot_attestation": boot_attestation,
            "boot_attestation_frames": boot_attestation_frames,
            "v024_temp_absence": v024_temp_absence,
            "v024_temp_absence_frames": temp_absence_frames,
            "selftest": selftest,
            "battery_capacity_percent": battery,
            "device_writes": {
                "stophud": True,
                "temporary_filesystem_mutations": True,
                "temporary_block_node_mutations": True,
                "temporary_mutation_paths": list(V024_NATIVE_TEMP_PATHS),
                "temporary_mutation_operations": [
                    "mkdir",
                    "mknodb",
                    "dd_to_temp",
                    "rm",
                    "absence_checks",
                ],
                "partition_writes": False,
                "mmio_writes": False,
                "controller_writes": False,
                "security_state_writes": False,
                "persistent_writes": False,
            },
        }
        raw_bytes = json_bytes(raw)
        write_new(raw_path, raw_bytes, 0o600)
        journal.update(
            {
                "status": "COMPLETE",
                "completed_utc": completed,
                "raw_sha256": sha256(raw_bytes),
                "raw_size": len(raw_bytes),
                "records": records,
            }
        )
        _atomic_json(journal_path, journal)
        journal_bytes = _stable_file_bytes(journal_path)
        journal_sha256 = sha256(journal_bytes)
        journal_size = len(journal_bytes)
    except BaseException as exc:
        if journal.get("status") != "INCIDENT":
            journal["status"] = "PREFLIGHT_FAILED"
            journal["error"] = f"{type(exc).__name__}: {exc}"
            journal["records"] = records
            _atomic_json(journal_path, journal)
        raise

    public = {
        "schema": "sdm855-a90-runtime-health-public-v2",
        "health_scope": "FINAL_ROLLBACK_ONLY",
        "experiment_id": args.experiment_id,
        "transport_module": LOCAL_TRANSPORT_MODULE,
        "transport_source": LOCAL_TRANSPORT_SOURCE,
        "started_utc": started,
        "completed_utc": journal["completed_utc"],
        "target_verified": True,
        "target_model": EXPECTED_MODEL,
        "soc": EXPECTED_SOC,
        "runtime": EXPECTED_RUNTIME,
        "version": EXPECTED_VERSION,
        "build": EXPECTED_RUNTIME_BUILD,
        "kernel": EXPECTED_KERNEL,
        "bootloader": EXPECTED_BOOTLOADER,
        "cmdline_debug_level": "0x4f4c",
        "cmdline_force_upload": "0x0",
        "cmdline_dump_sink": "0x0",
        "panic_on_oops": 1,
        "soc_id": 339,
        "boot_prefix_sha256": ROLLBACK_BOOT_SHA256,
        "boot_prefix_size": BOOT_PREFIX_SIZE,
        "boot_attestation": {
            "expected_sha256": boot_attestation["expected_sha256"],
            "captured_sha256": boot_attestation.get("captured_sha256"),
            "captured_size": boot_attestation.get("captured_size"),
            "cleanup_ok": boot_attestation.get("cleanup_ok"),
            "hash_matches_candidate": boot_attestation.get("hash_matches_candidate"),
            "size_matches_candidate": boot_attestation.get("size_matches_candidate"),
            "binding_event_count": len(boot_attestation.get("binding_events", [])),
        },
        "v024_temp_absence": {
            "paths_count": len(V024_NATIVE_TEMP_PATHS),
            "absence_verified": v024_temp_absence["absence_verified"],
            "frame_count": v024_temp_absence["frame_count"],
            "paths_sha256": sha256(json_bytes(list(V024_NATIVE_TEMP_PATHS))),
        },
        "selftest": selftest,
        "battery_capacity_percent": battery,
        "stophud_accepted": bool(stophud.get("accepted")),
        "stophud_busy_retries": stophud.get("busy_retries", 0),
        "stophud_device_state_write": True,
        "device_writes": {
            "stophud": True,
            "temporary_filesystem_mutations": True,
            "temporary_block_node_mutations": True,
            "partition_writes": False,
            "mmio_writes": False,
            "controller_writes": False,
            "security_state_writes": False,
            "persistent_writes": False,
        },
        "temporary_filesystem_mutations": True,
        "temporary_block_node_mutations": True,
        "partition_writes": False,
        "mmio_writes": False,
        "controller_writes": False,
        "security_state_writes": False,
        "persistent_writes": False,
        "records": [_public_record(record) for record in records],
        "stophud": stophud,
        "stophud_frames": [
            {
                key: record[key]
                for key in (
                    "evidence_id",
                    "argv",
                    "begin",
                    "end",
                    "payload_sha256",
                    "payload_size",
                    "transcript_sha256",
                    "transcript_size",
                )
                if key in record
            }
            for record in stophud_frames
        ],
        "raw_snapshot_sha256": sha256(raw_bytes),
        "raw_snapshot_size": len(raw_bytes),
        "journal_sha256": journal_sha256,
        "journal_size": journal_size,
        "private_record": {
            "filename": raw_path.name,
            "journal_filename": journal_path.name,
            "git_ignored": True,
        },
        "bridge_binding_verified": True,
        "limitations": [
            "The bounded current-boot proof mutates only fixed temporary filesystem/block-node paths and removes them before publication; those mutations are retained in the private record.",
            "Only idempotent stophud changes persistent device state; no partition, MMIO, controller, security-state, or persistent write is performed.",
            "The private record contains full transport frames; this manifest contains no payload base64 or serial identity.",
            "This receipt is a final-rollback health gate for the ca978... boot prefix; it does not attest the control candidate.",
        ],
    }
    write_new(manifest_path, json_bytes(public), 0o644)
    return raw_path, manifest_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default=BRIDGE_HOST)
    parser.add_argument("--port", type=int, default=BRIDGE_PORT)
    parser.add_argument("--timeout", type=float, default=15.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    raw, manifest = collect(args)
    print(raw)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
