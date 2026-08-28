#!/usr/bin/env python3
"""Apply or restore the exact A90 ``param.debuglevel`` four-byte transition.

The tool has two fixed actions: LOW->MID and MID->LOW.  It cannot accept a
partition, offset, value, block device, or payload path from the command line.
Before the one-shot effect it binds the exact runtime and GPT identity, verifies
the complete live partition bytes and their stable-range identity, verifies the
retained rollback artifact, and proves the exact Toybox ``dd`` semantics on a
temporary regular file.  It then writes four bytes once and requires the stable
post-write hash/fields to equal a host-derived expected image; full hashes are
retained as observations.  It never replays an ambiguous effect and
does not reboot the device.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import inspect
import json
import math
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from tools.a90_autohud_arbitration import run_stophud
    from tools.a90_pa28_live import revalidate_bridge_binding, validate_bridge_binding
    from tools.a90_param_capture import (
        PARAM_DEBUG_OFFSET,
        PARAM_CMDLINE_UPLOAD_OFFSET,
        PARAM_DEVNAME,
        PARAM_LOGICAL_BLOCK_SIZE,
        PARAM_MAJOR,
        PARAM_MINOR,
        PARAM_PARTNAME,
        PARAM_PARTITION_BYTES,
        PARAM_READ_ONLY,
        PARAM_SECTORS,
        PARAM_START_SECTOR,
        PARAM_STABLE_END,
        PARAM_STABLE_LOW_SHA256,
        PARAM_STABLE_MASK,
        PARAM_STABLE_MID_SHA256,
        PARAM_STABLE_OFFSET,
        PARAM_STABLE_SIZE,
        PARAM_STABLE_RANGE,
        PARAM_VOLATILE_RANGES,
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
        decode_fields,
        discover_param,
        parse_cmdline,
        stable_param_sha256,
        validate_runtime,
    )
    from tools.a90_partition_capture import (
        create_and_validate_node,
        binary_exchange,
        device_sha256,
        remove_node,
        parse_toybox_payload,
        run_toybox,
        text_exchange,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new  # type: ignore
    from a90_autohud_arbitration import run_stophud  # type: ignore
    from a90_pa28_live import (  # type: ignore
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    from a90_param_capture import (  # type: ignore
        PARAM_DEBUG_OFFSET,
        PARAM_CMDLINE_UPLOAD_OFFSET,
        PARAM_DEVNAME,
        PARAM_LOGICAL_BLOCK_SIZE,
        PARAM_MAJOR,
        PARAM_MINOR,
        PARAM_PARTNAME,
        PARAM_PARTITION_BYTES,
        PARAM_READ_ONLY,
        PARAM_SECTORS,
        PARAM_START_SECTOR,
        PARAM_STABLE_END,
        PARAM_STABLE_LOW_SHA256,
        PARAM_STABLE_MASK,
        PARAM_STABLE_MID_SHA256,
        PARAM_STABLE_OFFSET,
        PARAM_STABLE_SIZE,
        PARAM_STABLE_RANGE,
        PARAM_VOLATILE_RANGES,
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
        decode_fields,
        discover_param,
        parse_cmdline,
        stable_param_sha256,
        validate_runtime,
    )
    from a90_partition_capture import (  # type: ignore
        create_and_validate_node,
        binary_exchange,
        device_sha256,
        remove_node,
        parse_toybox_payload,
        run_toybox,
        text_exchange,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
ROLLBACK_IMAGE = (
    REPO_ROOT
    / "evidence/private/verification-006-a90-param-capture-20260825-01/param--sda10.bin"
)
ROLLBACK_SHA256 = "1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345"
MID_SHA256 = "50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256"
LOW_STABLE_SHA256 = PARAM_STABLE_LOW_SHA256
MID_STABLE_SHA256 = PARAM_STABLE_MID_SHA256

LOW_BYTES = b"DLOW"
MID_BYTES = b"DMID"
PAYLOAD_PATH = "/tmp/sdm855_mblab_param_debug_payload"
SMOKE_PATH = "/tmp/sdm855_mblab_param_debug_dd_smoke"
PARAM_NODE_PATH = "/dev/sdm855_mblab_sda10"
DD_BLOCK_SIZE = 4
DD_SEEK_BLOCKS = PARAM_DEBUG_OFFSET // DD_BLOCK_SIZE
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SHA_LINE_RE = re.compile(rb"(?m)^([0-9a-f]{64})  (/.+?)\r?$")
PAYLOAD_SHA_LINE_RE = re.compile(
    rb"(?m)^([0-9a-f]{64})  (/tmp/sdm855_mblab_param_debug_payload)\r?$"
)
MAX_COMMAND_TIMEOUT = 120.0
MAX_HASH_TIMEOUT = 180.0
MAX_CAPTURE_TIMEOUT = 600.0
MAX_EFFECT_TIMEOUT = 120.0
EFFECT_CONSUMPTION_DIRNAME = ".param-debug-effect-consumption"
EFFECT_CONSUMPTION_SCHEMA = "sdm855-a90-param-debug-effect-consumption-v1"
EFFECT_CLAIM_SUFFIX = ".claim.json"


@dataclass(frozen=True)
class Transition:
    action: str
    before_bytes: bytes
    after_bytes: bytes
    before_sha256: str
    after_sha256: str
    before_stable_sha256: str
    after_stable_sha256: str
    before_label: str
    after_label: str


TRANSITIONS = {
    "apply-mid": Transition(
        "apply-mid",
        LOW_BYTES,
        MID_BYTES,
        ROLLBACK_SHA256,
        MID_SHA256,
        LOW_STABLE_SHA256,
        MID_STABLE_SHA256,
        "LOW",
        "MID",
    ),
    "restore-low": Transition(
        "restore-low",
        MID_BYTES,
        LOW_BYTES,
        MID_SHA256,
        ROLLBACK_SHA256,
        MID_STABLE_SHA256,
        LOW_STABLE_SHA256,
        "MID",
        "LOW",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bridge_bindings_match(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Compare pinned bridge identity while ignoring validation timestamp."""

    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def derive_images(path: Path = ROLLBACK_IMAGE) -> tuple[bytes, bytes]:
    original = path.read_bytes()
    if len(original) != PARAM_PARTITION_BYTES:
        raise ValueError("rollback image is not exactly 10 MiB")
    if sha256(original) != ROLLBACK_SHA256:
        raise ValueError("rollback image SHA-256 differs from the pinned capture")
    if stable_param_sha256(original) != LOW_STABLE_SHA256:
        raise ValueError("rollback image stable SHA-256 differs from the fixed mask pin")
    if original[PARAM_DEBUG_OFFSET : PARAM_DEBUG_OFFSET + 4] != LOW_BYTES:
        raise ValueError("rollback image does not contain DLOW at the exact field")
    modified = bytearray(original)
    modified[PARAM_DEBUG_OFFSET : PARAM_DEBUG_OFFSET + 4] = MID_BYTES
    modified_bytes = bytes(modified)
    if sha256(modified_bytes) != MID_SHA256:
        raise ValueError("host-derived MID image SHA-256 differs from the pin")
    if stable_param_sha256(modified_bytes) != MID_STABLE_SHA256:
        raise ValueError("host-derived MID stable SHA-256 differs from the fixed mask pin")
    differences = [
        offset
        for offset, (before, after) in enumerate(zip(original, modified_bytes))
        if before != after
    ]
    if differences != [PARAM_DEBUG_OFFSET + 1, PARAM_DEBUG_OFFSET + 2, PARAM_DEBUG_OFFSET + 3]:
        raise ValueError(f"unexpected host image delta: {differences}")
    return original, modified_bytes


def transition_images(
    transition: Transition, original: bytes, modified: bytes
) -> tuple[bytes, bytes]:
    if transition.action == "apply-mid":
        return original, modified
    if transition.action == "restore-low":
        return modified, original
    raise ValueError(f"unsupported transition: {transition.action}")


def fixed_dd_args(input_path: str, output_path: str) -> tuple[str, ...]:
    return (
        "dd",
        f"if={input_path}",
        f"of={output_path}",
        f"bs={DD_BLOCK_SIZE}",
        "count=1",
        f"seek={DD_SEEK_BLOCKS}",
        "conv=notrunc,fsync",
        "status=none",
    )


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject an existing symlink in a fixed evidence path."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    current = Path(lexical.anchor or "/")
    for component in lexical.parts[1:] if lexical.is_absolute() else lexical.parts:
        current /= component
        try:
            if current.is_symlink():
                raise RuntimeError(f"{label} component must not be a symlink: {current}")
        except OSError as exc:
            raise RuntimeError(f"{label} component cannot be inspected: {current}") from exc


def _atomic_replace_json(path: Path, value: object, mode: int = 0o600) -> None:
    data = json_bytes(value)
    _reject_symlink_components(path, "journal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(f"journal temporary already exists: {temporary}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _write_initial_json(path: Path, value: object, mode: int = 0o600) -> None:
    """Claim a transition journal path exactly once before effect work."""

    data = json_bytes(value)
    _reject_symlink_components(path, "initial journal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        # Leave a partially created final journal in place.  Its existence is
        # the ownership/no-replay signal if a host crash occurs at this point.
        raise


def _validate_timeout(value: object, label: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
        or float(value) > maximum
    ):
        raise ValueError(f"{label} must be finite, positive, and <= {maximum:g}s")
    return float(value)


def _effect_claim_key(
    action: str, before_hash: str, partition, start_sector: int
) -> str:
    """Derive a semantic fixed claim key without caller JSON formatting."""

    if action not in TRANSITIONS:
        raise ValueError("effect claim action is not fixed")
    if not isinstance(before_hash, str) or re.fullmatch(r"[0-9a-f]{64}", before_hash) is None:
        raise ValueError("effect claim preimage hash is not exact")
    _require_exact_partition(partition, start_sector)
    # Accept the two historical complete-image pins at this boundary only as
    # compatibility input; canonicalize them to their stable identities so a
    # byte-0 variant cannot create a second physical-claim namespace.
    stable_before_hash = {
        ROLLBACK_SHA256: LOW_STABLE_SHA256,
        MID_SHA256: MID_STABLE_SHA256,
    }.get(before_hash, before_hash)
    fields = (
        "stable-param-mask-v1",
        "excluded=0:1",
        f"stable={PARAM_STABLE_OFFSET}:{PARAM_STABLE_END}",
        action,
        stable_before_hash,
        PARAM_PARTNAME,
        PARAM_DEVNAME,
        PARAM_MAJOR,
        PARAM_MINOR,
        PARAM_SECTORS,
        PARAM_PARTITION_BYTES,
        PARAM_READ_ONLY,
        PARAM_LOGICAL_BLOCK_SIZE,
        PARAM_START_SECTOR,
    )
    # These separators/order are fixed code constants; no caller JSON
    # serialization can produce a second semantic key for the same effect.
    canonical = "|".join(str(item) for item in fields).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _effect_claim_path(
    action: str,
    before_hash: str,
    partition,
    start_sector: int,
    *,
    root: Path | None = None,
) -> Path:
    key = _effect_claim_key(action, before_hash, partition, start_sector)
    directory = (
        Path(REPO_ROOT if root is None else root).resolve()
        / "evidence"
        / "private"
        / EFFECT_CONSUMPTION_DIRNAME
    )
    _reject_symlink_components(directory, "effect-consumption directory")
    return directory / f"{key}{EFFECT_CLAIM_SUFFIX}"


def _claim_effect_consumption(
    action: str,
    before_hash: str,
    partition,
    start_sector: int,
    experiment_id: str,
    *,
    root: Path | None = None,
    full_preimage_hash: str | None = None,
) -> dict[str, object]:
    """O_EXCL-claim one semantic param transition before marker/dispatch."""

    if SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise ValueError("effect claim experiment ID is not safe")
    if full_preimage_hash is not None and re.fullmatch(
        r"[0-9a-f]{64}", full_preimage_hash
    ) is None:
        raise ValueError("effect claim full preimage hash is not exact")
    stable_before_hash = {
        ROLLBACK_SHA256: LOW_STABLE_SHA256,
        MID_SHA256: MID_STABLE_SHA256,
    }.get(before_hash, before_hash)
    observed_full_hash = full_preimage_hash
    if observed_full_hash is None and before_hash != stable_before_hash:
        observed_full_hash = before_hash
    key = _effect_claim_key(action, stable_before_hash, partition, start_sector)
    path = (
        Path(REPO_ROOT if root is None else root).resolve()
        / "evidence"
        / "private"
        / EFFECT_CONSUMPTION_DIRNAME
        / f"{key}{EFFECT_CLAIM_SUFFIX}"
    )
    directory = path.parent
    _reject_symlink_components(directory, "effect-consumption directory")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    claim = {
        "schema": EFFECT_CONSUMPTION_SCHEMA,
        "key": key,
        "action": action,
        "preimage_sha256": stable_before_hash,
        "preimage_full_sha256": observed_full_hash,
        "stable_preimage_sha256": stable_before_hash,
        "stable_mask": {
            "excluded_ranges": [[0, 1]],
            "stable_ranges": [[1, PARAM_PARTITION_BYTES]],
            "stable_size": PARAM_STABLE_SIZE,
        },
        "partition": {
            "partname": PARAM_PARTNAME,
            "devname": PARAM_DEVNAME,
            "major": PARAM_MAJOR,
            "minor": PARAM_MINOR,
            "sectors": PARAM_SECTORS,
            "byte_size": PARAM_PARTITION_BYTES,
            "read_only": PARAM_READ_ONLY,
            "logical_block_size": PARAM_LOGICAL_BLOCK_SIZE,
            "start_sector": PARAM_START_SECTOR,
        },
        "experiment_id": experiment_id,
        "effect_replayed": False,
        "created_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
    }
    data = json_bytes(claim)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(directory, directory_flags)
        descriptor = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError as exc:
        try:
            os.close(directory_fd)
        except (OSError, UnboundLocalError):
            pass
        raise RuntimeError(
            "semantic param effect claim already exists; concurrent/replayed effect refused"
        ) from exc
    except OSError as exc:
        try:
            os.close(directory_fd)
        except (OSError, UnboundLocalError):
            pass
        raise RuntimeError(
            f"semantic param effect claim cannot be created: {path}"
        ) from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("semantic param effect claim write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        # Keep any final/partial claim.  A crash after O_EXCL creation is a
        # no-replay boundary even if the host cannot finish writing it.
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
        try:
            os.close(directory_fd)
        except OSError:
            pass
        raise RuntimeError(
            "semantic param effect claim directory fsync failed"
        ) from exc
    else:
        os.close(directory_fd)
    return {
        "filename": path.name,
        "path": str(path),
        "sha256": sha256(data),
        "size": len(data),
        **claim,
    }


def _public_effect_claim(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        key: value.get(key)
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
        )
    }


def _effect_claim_stub(
    path: Path,
    key: str,
    action: str,
    before_hash: str,
    partition,
    start_sector: int,
    experiment_id: str,
) -> dict[str, object]:
    """Retain a conservative receipt when O_EXCL claim publication fails."""

    stable_before_hash = {
        ROLLBACK_SHA256: LOW_STABLE_SHA256,
        MID_SHA256: MID_STABLE_SHA256,
    }.get(before_hash, before_hash)

    return {
        "filename": path.name,
        "path": str(path),
        "sha256": None,
        "size": None,
        "schema": EFFECT_CONSUMPTION_SCHEMA,
        "key": key,
        "action": action,
        "preimage_sha256": stable_before_hash,
        "preimage_full_sha256": (
            before_hash if before_hash != stable_before_hash else None
        ),
        "stable_preimage_sha256": stable_before_hash,
        "stable_mask": {
            "excluded_ranges": [[0, 1]],
            "stable_ranges": [[1, PARAM_PARTITION_BYTES]],
            "stable_size": PARAM_STABLE_SIZE,
        },
        "partition": {**asdict(partition), "start_sector": start_sector},
        "experiment_id": experiment_id,
        "effect_replayed": False,
        "claim_write_failed": True,
    }


def _supports_before_mutation(function: object) -> bool:
    """Inspect a callable/test seam without invoking it speculatively."""

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


def _invoke_with_binding(
    function,
    positional: tuple[object, ...],
    binding,
    label: str,
):
    """Pass the callback to real helpers, preserving narrow test doubles.

    No retry occurs after a helper invocation.  A side-effect test seam that
    deliberately exposes only ``*args`` gets the same fresh check immediately
    before the call, while production helpers receive the callback for each
    internal mutation group.
    """

    if _supports_before_mutation(function):
        return function(*positional, before_mutation=binding)
    binding(label)
    return function(*positional)


def _publish_incident_manifest(
    path: Path,
    *,
    experiment_id: str,
    started: str,
    status: str,
    error: object,
    journal_path: Path,
    target_verified: bool = False,
    target: Mapping[str, object] | None = None,
    effect_dispatched: bool = False,
    effect_consumption_claim: object = None,
) -> None:
    manifest = {
        "schema": "sdm855-a90-param-debug-transition-public-v1",
        "experiment_id": experiment_id,
        "started_utc": started,
        "completed_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "status": status,
        "classification": status,
        "expected_target": {
            "model": TARGET_MODEL,
            "soc": TARGET_SOC,
            "bootloader": TARGET_BOOTLOADER,
            "runtime": TARGET_RUNTIME,
            "kernel": TARGET_KERNEL,
        },
        "target": dict(target) if target_verified and target is not None else None,
        "target_verified": bool(target_verified),
        "journal": journal_path.name,
        "effect_dispatched": bool(effect_dispatched),
        "effect_dispatched_count": 1 if effect_dispatched else 0,
        "effect_replayed": False,
        "effect_consumption_claim": _public_effect_claim(effect_consumption_claim),
        "effect_consumption_claim_path": (
            effect_consumption_claim.get("filename")
            if isinstance(effect_consumption_claim, Mapping)
            else None
        ),
        "partition_writes": bool(effect_dispatched),
        "error": str(error),
        "redaction": {
            "raw_cmdline": "omitted",
            "serial_identity": "omitted",
            "raw_transcript": "omitted",
            "payload_base64": "omitted",
        },
    }
    write_new(path, json_bytes(manifest), 0o644)


def _remove_temp(
    host: str,
    port: int,
    path: str,
    timeout: float,
    evidence: str,
    *,
    before_mutation=None,
) -> None:
    if path not in {PAYLOAD_PATH, SMOKE_PATH}:
        raise ValueError(f"temporary path is not fixed: {path!r}")
    if before_mutation is not None:
        before_mutation(f"{evidence}_rm")
    rm_payload = run_toybox(host, port, evidence, ("rm", "-f", path), timeout)
    if parse_toybox_payload(rm_payload, evidence) not in (b"", b"\n"):
        raise ValueError(f"{evidence} returned unexpected rm output")
    for index, test_args in enumerate(
        (("test", "!", "-e", path), ("test", "!", "-L", path)), 1
    ):
        if before_mutation is not None:
            before_mutation(f"{evidence}_absent_{index}")
        check_evidence = f"{evidence}_absent_{index}"
        output = parse_toybox_payload(
            run_toybox(host, port, check_evidence, test_args, timeout),
            check_evidence,
        )
        if output not in (b"", b"\n"):
            raise ValueError(f"{check_evidence} returned unexpected output")


def _write_ascii_payload(
    host: str,
    port: int,
    path: str,
    payload: bytes,
    timeout: float,
    *,
    before_mutation=None,
) -> dict[str, object]:
    text = payload.decode("ascii", errors="strict")
    _remove_temp(
        host,
        port,
        path,
        timeout,
        "payload_cleanup_before",
        before_mutation=before_mutation,
    )
    if before_mutation is not None:
        before_mutation("payload_touch")
    touch_output = parse_toybox_payload(
        run_toybox(host, port, "payload_touch", ("touch", path), timeout),
        "payload_touch",
    )
    if touch_output not in (b"", b"\n"):
        raise ValueError("payload_touch returned unexpected output")
    if before_mutation is not None:
        before_mutation("payload_write")
    text_exchange(host, port, "payload_write", ("writefile", path, text), timeout)
    stat = text_exchange(host, port, "payload_stat", ("stat", path), timeout)
    if b"size=4" not in stat:
        raise ValueError(f"payload stat does not report exact size 4: {stat!r}")
    readback = text_exchange(host, port, "payload_readback", ("cat", path), timeout)
    if readback != payload:
        raise ValueError(f"payload readback mismatch: {readback!r}")
    hash_payload = run_toybox(
        host, port, "payload_sha256", ("sha256sum", path), timeout
    )
    matches = SHA_LINE_RE.findall(hash_payload)
    hashes = [digest.decode("ascii") for digest, item in matches if item == path.encode()]
    if hashes != [sha256(payload)]:
        raise ValueError(f"payload SHA-256 mismatch: {hashes}")
    return {
        "path": path,
        "size": len(payload),
        "sha256": hashes[0],
        "readback_base64": base64.b64encode(readback).decode("ascii"),
    }


def verify_regular_file_dd(
    host: str,
    port: int,
    payload_path: str,
    payload: bytes,
    timeout: float,
    *,
    before_mutation=None,
) -> dict[str, object]:
    _remove_temp(
        host,
        port,
        SMOKE_PATH,
        timeout,
        "smoke_cleanup_before",
        before_mutation=before_mutation,
    )
    if before_mutation is not None:
        before_mutation("smoke_touch")
    touch_output = parse_toybox_payload(
        run_toybox(host, port, "smoke_touch", ("touch", SMOKE_PATH), timeout),
        "smoke_touch",
    )
    if touch_output not in (b"", b"\n"):
        raise ValueError("smoke_touch returned unexpected output")
    if before_mutation is not None:
        before_mutation("smoke_seed")
    text_exchange(
        host,
        port,
        "smoke_seed",
        ("writefile", SMOKE_PATH, "AAAABBBBCCCC"),
        timeout,
    )
    args = (
        "dd",
        f"if={payload_path}",
        f"of={SMOKE_PATH}",
        "bs=4",
        "count=1",
        "seek=1",
        "conv=notrunc,fsync",
        "status=none",
    )
    if before_mutation is not None:
        before_mutation("smoke_dd")
    frame = exchange(
        host,
        port,
        Command("smoke_dd", ("run", "/bin/toybox", *args)),
        timeout,
        allow_error=True,
    )
    readback = text_exchange(host, port, "smoke_readback", ("cat", SMOKE_PATH), timeout)
    expected = b"AAAA" + payload + b"CCCC"
    if int(frame.end["rc"], 0) != 0 or frame.end["status"] != "ok":
        raise ValueError(f"regular-file dd smoke failed: {frame.end}")
    if readback != expected:
        raise ValueError(f"regular-file dd semantics changed: {readback!r}")
    _remove_temp(
        host,
        port,
        SMOKE_PATH,
        timeout,
        "smoke_cleanup_after",
        before_mutation=before_mutation,
    )
    return {
        "args": list(args),
        "a90p1_end": frame.end,
        "expected_sha256": sha256(expected),
        "readback_sha256": sha256(readback),
        "passed": True,
    }


def _partition_record(partition, start_sector: int) -> dict[str, object]:
    values = asdict(partition)
    values["start_sector"] = start_sector
    return values


def _require_exact_partition(partition, start_sector: int) -> None:
    expected = {
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
    try:
        actual = _partition_record(partition, start_sector)
    except BaseException as exc:
        raise ValueError("live param geometry object is malformed") from exc
    if any(
        type(actual.get(key)) is not type(value) or actual.get(key) != value
        for key, value in expected.items()
    ):
        raise ValueError(f"live param geometry is not exact: {actual!r}")


def _require_stat_rdev(stat_payload: bytes, partition) -> dict[str, object]:
    if type(stat_payload) is not bytes:
        raise ValueError("param block-node stat is not bytes")
    if len(stat_payload) > 256:
        raise ValueError("param block-node stat exceeds the fixed size bound")
    try:
        text = stat_payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("param block-node stat is not strict ASCII") from exc
    if "\x00" in text:
        raise ValueError("param block-node stat contains malformed line framing")
    # Normalize only CRLF pairs, then compare one exact two-line record.  The
    # live native stat receipt uses CRLF between lines and no final LF; one
    # terminal LF remains accepted for retained fixtures.  Bare CR, empty or
    # extra lines, duplicate/unknown fields, spacing changes, and rdev
    # prefix/suffix lookalikes therefore fail closed.
    normalized = stat_payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise ValueError("param block-node stat contains malformed line framing")
    expected_metadata = b"mode=0600 uid=0 gid=0 size=0"
    expected_rdev = f"rdev={partition.major}:{partition.minor}"
    expected_rdev_bytes = expected_rdev.encode("ascii")
    allowed = {
        expected_metadata + b"\n" + expected_rdev_bytes,
        expected_metadata + b"\n" + expected_rdev_bytes + b"\n",
    }
    if normalized not in allowed:
        raise ValueError(f"param block-node stat record is not exact: {text!r}")
    return {
        "raw": text,
        "mode": "0600",
        "uid": "0",
        "gid": "0",
        "size": "0",
        "rdev": expected_rdev,
    }


def _verify_staged_payload(
    host: str,
    port: int,
    payload_path: str,
    payload: bytes,
    timeout: float,
    *,
    expected_record: Mapping[str, object] | None = None,
    evidence_prefix: str = "payload_final",
) -> dict[str, object]:
    """Freshly stat/read/hash the fixed staged payload immediately pre-dd."""

    if (
        payload_path != PAYLOAD_PATH
        or type(payload) is not bytes
        or payload not in {LOW_BYTES, MID_BYTES}
    ):
        raise ValueError("staged payload is not the fixed transition payload")
    expected_hash = sha256(payload)
    if expected_record is not None:
        required = {
            "path": payload_path,
            "size": len(payload),
            "sha256": expected_hash,
        }
        for key, value in required.items():
            if expected_record.get(key) != value:
                raise ValueError(f"staged payload receipt changed at {key}")

    link_check = parse_toybox_payload(
        run_toybox(
            host,
            port,
            f"{evidence_prefix}_nofollow",
            ("test", "!", "-L", payload_path),
            timeout,
        ),
        f"{evidence_prefix}_nofollow",
    )
    if link_check not in (b"", b"\n"):
        raise ValueError("staged payload path is a symlink")
    stat_payload = text_exchange(
        host, port, f"{evidence_prefix}_stat", ("stat", payload_path), timeout
    )
    if type(stat_payload) is not bytes:
        raise ValueError("staged payload stat is not bytes")
    try:
        stat_text = stat_payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("staged payload stat is not strict ASCII") from exc
    normalized_stat = stat_text.replace("\r\n", "\n")
    if normalized_stat.endswith("\n"):
        normalized_stat = normalized_stat[:-1]
    stat_lines = normalized_stat.split("\n")
    if len(stat_lines) != 1 or not stat_lines[0]:
        raise ValueError("staged payload stat must contain exactly one metadata line")
    stat_fields: dict[str, str] = {}
    for token in stat_lines[0].split():
        if "=" not in token:
            raise ValueError(f"staged payload stat has malformed token: {token!r}")
        key, value = token.split("=", 1)
        if key in stat_fields or key not in {"mode", "uid", "gid", "size"}:
            raise ValueError(f"staged payload stat has duplicate/unknown key: {key!r}")
        stat_fields[key] = value
    if set(stat_fields) != {"mode", "uid", "gid", "size"}:
        raise ValueError("staged payload stat metadata fields are incomplete")
    if re.fullmatch(r"0[0-7]+", stat_fields["mode"]) is None:
        raise ValueError(f"staged payload mode is malformed: {stat_fields['mode']!r}")
    for key in ("uid", "gid", "size"):
        if re.fullmatch(r"[0-9]+", stat_fields[key]) is None:
            raise ValueError(f"staged payload {key} is malformed: {stat_fields[key]!r}")
    if stat_fields["size"] != "4":
        raise ValueError(f"staged payload size is not exactly 4: {stat_fields!r}")
    readback = text_exchange(
        host, port, f"{evidence_prefix}_readback", ("cat", payload_path), timeout
    )
    if type(readback) is not bytes:
        raise ValueError("staged payload readback is not bytes")
    if readback != payload:
        raise ValueError(f"staged payload bytes changed: {readback!r}")
    raw_hash = run_toybox(
        host,
        port,
        f"{evidence_prefix}_sha256",
        ("sha256sum", payload_path),
        timeout,
    )
    if type(raw_hash) is not bytes:
        raise ValueError("staged payload SHA-256 receipt is not bytes")
    body = parse_toybox_payload(raw_hash, f"{evidence_prefix}_sha256")
    matches = PAYLOAD_SHA_LINE_RE.findall(body)
    hashes = [digest.decode("ascii") for digest, path in matches if path == payload_path.encode()]
    if hashes != [expected_hash]:
        raise ValueError(f"staged payload SHA-256 is not exact: {hashes!r}")
    return {
        "path": payload_path,
        "size": len(payload),
        "sha256": expected_hash,
        "stat": normalized_stat,
        "readback_sha256": sha256(readback),
    }


def verify_exact_param_target(
    host: str,
    port: int,
    partition,
    start_sector: int,
    payload_path: str,
    payload: bytes,
    timeout: float,
    *,
    expected_record: Mapping[str, object] | None = None,
    evidence_prefix: str = "effect_target",
) -> dict[str, object]:
    """Revalidate node rdev, complete param geometry, and staged bytes/hash."""

    try:
        node_path = partition.node_path
    except AttributeError as exc:
        raise ValueError("param block-node binding is malformed") from exc
    if node_path != PARAM_NODE_PATH:
        raise ValueError(f"param block-node path is not fixed: {node_path!r}")
    _require_exact_partition(partition, start_sector)
    node_stat_payload = text_exchange(
        host,
        port,
        f"{evidence_prefix}_node_stat",
        ("stat", partition.node_path),
        timeout,
    )
    node_stat = _require_stat_rdev(node_stat_payload, partition)
    current_partition, current_start = discover_param(host, port, timeout)
    _require_exact_partition(current_partition, current_start)
    if _partition_record(current_partition, current_start) != _partition_record(
        partition, start_sector
    ):
        raise ValueError("param geometry changed after node stat")
    staged = _verify_staged_payload(
        host,
        port,
        payload_path,
        payload,
        timeout,
        expected_record=expected_record,
        evidence_prefix=f"{evidence_prefix}_payload",
    )
    return {
        "node": node_stat,
        "partition": _partition_record(current_partition, current_start),
        "payload": staged,
    }


def _preflight(args: argparse.Namespace) -> tuple[dict[str, str], str, object, int]:
    version_frame = exchange(
        args.host, args.port, Command("version", ("version",)), args.command_timeout
    )
    cmdline_frame = exchange(
        args.host,
        args.port,
        Command("proc_cmdline", ("cat", "/proc/cmdline")),
        args.command_timeout,
    )
    cmdline = parse_cmdline(cmdline_frame.payload)
    validate_runtime(version_frame.payload, cmdline)
    if cmdline.get("androidboot.force_upload") != "0x0":
        raise ValueError("force_upload changed from the required zero state")
    if cmdline.get("sec_debug.dump_sink") != "0x0":
        raise ValueError("dump_sink changed from the required USB-default state")
    if cmdline.get("androidboot.upload_offset") != PARAM_CMDLINE_UPLOAD_OFFSET:
        raise ValueError("upload_offset changed from the exact capture contract")
    dload_frame = exchange(
        args.host,
        args.port,
        Command(
            "download_mode",
            ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
        ),
        args.command_timeout,
    )
    dload = dload_frame.payload.decode("ascii", errors="strict").strip()
    if dload != "1":
        raise ValueError("download_mode is not 1")
    partition, start_sector = discover_param(args.host, args.port, args.command_timeout)
    _require_exact_partition(partition, start_sector)
    return cmdline, dload, partition, start_sector


def _capture_exact_param_image(
    host: str,
    port: int,
    partition,
    timeout: float,
    label: str,
) -> dict[str, object]:
    """Capture one complete image through the bounded binary exchange path."""

    result = binary_exchange(
        host,
        port,
        partition.node_path,
        PARAM_PARTITION_BYTES,
        timeout,
    )
    if isinstance(result, tuple) and len(result) == 2:
        end_fields, image = result
    else:
        end_fields, image = None, result
    if type(image) is not bytes or len(image) != PARAM_PARTITION_BYTES:
        raise ValueError(
            f"{label} capture is not exactly {PARAM_PARTITION_BYTES} bytes"
        )
    full_hash = sha256(image)
    stable_hash = stable_param_sha256(image)
    return {
        "label": label,
        "size": len(image),
        "sha256": full_hash,
        "full_sha256": full_hash,
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
        "a90p1_end": dict(end_fields) if isinstance(end_fields, Mapping) else end_fields,
        "image": image,
    }


def execute(args: argparse.Namespace) -> tuple[Path, Path]:
    if getattr(args, "execute", False) is not True:
        raise ValueError("persistent transition requires explicit --execute")
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("invalid experiment ID")
    if args.host != "127.0.0.1" or args.port != 54321:
        raise ValueError("transition only accepts the pinned 127.0.0.1:54321 bridge")
    command_timeout = _validate_timeout(
        args.command_timeout, "command-timeout", MAX_COMMAND_TIMEOUT
    )
    hash_timeout = _validate_timeout(args.hash_timeout, "hash-timeout", MAX_HASH_TIMEOUT)
    capture_timeout = _validate_timeout(
        getattr(args, "capture_timeout", hash_timeout),
        "capture-timeout",
        MAX_CAPTURE_TIMEOUT,
    )
    effect_timeout = _validate_timeout(
        args.effect_timeout, "effect-timeout", MAX_EFFECT_TIMEOUT
    )
    # Keep the existing helper/test seam while ensuring every downstream
    # timeout is the finite, bounded value validated above.
    args.command_timeout = command_timeout
    args.hash_timeout = hash_timeout
    args.capture_timeout = capture_timeout
    args.effect_timeout = effect_timeout
    if hasattr(args, "output_root"):
        supplied_value = getattr(args, "output_root")
        if not isinstance(supplied_value, (str, os.PathLike)):
            raise ValueError("transition output root is fixed to REPO_ROOT")
        supplied_root = Path(supplied_value).resolve()
        if supplied_root != REPO_ROOT.resolve():
            raise ValueError("transition output root is fixed to REPO_ROOT")
    transition = TRANSITIONS[args.action]
    original, modified = derive_images()
    before_image, after_image = transition_images(transition, original, modified)
    # ``derive_images`` authenticates the retained host artifact using its
    # complete historical pins.  The live transition gate below is semantic:
    # byte-0 variants are valid observations, so the live image is not required
    # to reproduce either historical full-image digest.
    if stable_param_sha256(before_image) != transition.before_stable_sha256:
        raise ValueError("transition before stable-image pin mismatch")
    if stable_param_sha256(after_image) != transition.after_stable_sha256:
        raise ValueError("transition after stable-image pin mismatch")
    before_fields = decode_fields(before_image)
    after_fields = decode_fields(after_image)
    if before_fields["debuglevel"]["label"] != transition.before_label:
        raise ValueError("before debug label mismatch")
    if after_fields["debuglevel"]["label"] != transition.after_label:
        raise ValueError("after debug label mismatch")
    for name in ("force_upload_flag", "FMM_lock", "dump_sink"):
        if before_fields[name]["value"] != after_fields[name]["value"]:
            raise ValueError(f"non-debug field changed in host model: {name}")

    root = REPO_ROOT.resolve()
    journal_path = root / "evidence/private" / f"{args.experiment_id}.journal.json"
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    if journal_path.exists() or manifest_path.exists():
        raise FileExistsError("transition evidence already exists; effects are never replayed")

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    stophud_frames: list[dict[str, object]] = []
    journal: dict[str, object] = {
        "schema": "sdm855-a90-param-debug-transition-journal-v1",
        "experiment_id": args.experiment_id,
        "action": transition.action,
        "started_utc": started,
        "status": "STOPHUD_INTENT_DURABLE",
        "effect_dispatched": False,
        "effect_dispatched_count": 0,
        "effect_replayed": False,
        "write_count": 0,
        "partition_writes": False,
        "cleanup_deferred": False,
        "reconcile_required": False,
        "cleanup_attempted": False,
        "cleanup_completed": False,
        "node_cleanup_verified": False,
        "effect_consumption_claim": None,
        "effect_consumption_claim_path": None,
        "stophud": None,
        "stophud_frames": stophud_frames,
        "expected_target": {
            "model": TARGET_MODEL,
            "soc": TARGET_SOC,
            "bootloader": TARGET_BOOTLOADER,
            "runtime": TARGET_RUNTIME,
            "kernel": TARGET_KERNEL,
        },
        "target": None,
        "target_verified": False,
    }
    _write_initial_json(journal_path, journal)

    def persist_stophud(attempts: list[dict[str, object]]) -> None:
        journal["stophud_attempts"] = attempts
        journal["stophud_frames"] = stophud_frames
        _atomic_replace_json(journal_path, journal)

    incident_published = False

    def publish_incident(error: object) -> None:
        nonlocal incident_published
        if incident_published or manifest_path.exists() or manifest_path.is_symlink():
            return
        target = journal.get("target")
        _publish_incident_manifest(
            manifest_path,
            experiment_id=args.experiment_id,
            started=started,
            status=str(journal.get("status", "INCIDENT")),
            error=error,
            journal_path=journal_path,
            target_verified=bool(journal.get("target_verified")),
            target=target if isinstance(target, Mapping) else None,
            effect_dispatched=bool(journal.get("effect_dispatched")),
            effect_consumption_claim=journal.get("effect_consumption_claim"),
        )
        incident_published = True

    bridge_binding: Mapping[str, object] | None = None
    try:
        # Bind the exact operator-owned bridge before the first stateful
        # arbitration command.  A binding failure is host-only and therefore
        # results in zero transport/device commands.
        bridge_binding = validate_bridge_binding()
        if not isinstance(bridge_binding, Mapping):
            raise ValueError("initial bridge binding is not an object")
        journal["bridge_binding"] = dict(bridge_binding)
        _atomic_replace_json(journal_path, journal)
        # Revalidate the exact bridge directly adjacent to stophud.  On a
        # successful check there is no host fsync or unrelated command between
        # this call and the first stateful arbitration exchange.
        current_binding = revalidate_bridge_binding(bridge_binding)
        if not isinstance(current_binding, Mapping) or not _bridge_bindings_match(
            bridge_binding, current_binding
        ):
            raise RuntimeError("bridge binding drifted immediately before stophud")

        def stophud_exchange(host, port, command, timeout, **kwargs):
            # ``run_stophud`` may retry only a bounded busy refusal.  Bind the
            # exact original bridge immediately before every attempt so a
            # later retry cannot cross a bridge identity change.
            current = revalidate_bridge_binding(bridge_binding)
            if not isinstance(current, Mapping) or not _bridge_bindings_match(
                bridge_binding, current
            ):
                raise RuntimeError("bridge binding drifted before stophud attempt")
            return exchange(host, port, command, timeout, **kwargs)

        stophud = run_stophud(
            args.host,
            args.port,
            args.command_timeout,
            stophud_exchange,
            frame_records=stophud_frames,
            persist=persist_stophud,
        )
        journal["stophud"] = stophud
        cmdline, dload, partition, start_sector = _preflight(args)
        journal["target"] = {
            "model": TARGET_MODEL,
            "soc": TARGET_SOC,
            "bootloader": TARGET_BOOTLOADER,
            "runtime": TARGET_RUNTIME,
            "kernel": TARGET_KERNEL,
        }
        journal["target_verified"] = True
        _atomic_replace_json(journal_path, journal)
    except BaseException as exc:
        journal["status"] = "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
        journal["error"] = f"{type(exc).__name__}: {exc}"
        _atomic_replace_json(journal_path, journal)
        publish_incident(exc)
        raise
    try:
        if args.action == "apply-mid" and cmdline.get("androidboot.debug_level") != "0x4f4c":
            raise ValueError("apply preflight cmdline is not LOW")
        if args.action == "restore-low" and cmdline.get("androidboot.debug_level") not in {
            "0x4f4c",
            "0x494d",
        }:
            raise ValueError("restore preflight cmdline is neither LOW nor MID")
    except BaseException as exc:
        journal["status"] = "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
        journal["error"] = f"{type(exc).__name__}: {exc}"
        _atomic_replace_json(journal_path, journal)
        publish_incident(exc)
        raise

    journal = {
        "schema": "sdm855-a90-param-debug-transition-journal-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "action": transition.action,
        "status": "PREFLIGHT",
        "effect_dispatched": False,
        "effect_dispatched_count": 0,
        "effect_replayed": False,
        "write_count": 0,
        "partition_writes": False,
        "cleanup_deferred": False,
        "reconcile_required": False,
        "cleanup_attempted": False,
        "cleanup_completed": False,
        "node_cleanup_verified": False,
        "expected_target": {
            "model": TARGET_MODEL,
            "soc": TARGET_SOC,
            "bootloader": TARGET_BOOTLOADER,
            "runtime": TARGET_RUNTIME,
            "kernel": TARGET_KERNEL,
        },
        "target": {
            "model": TARGET_MODEL,
            "soc": TARGET_SOC,
            "bootloader": TARGET_BOOTLOADER,
            "runtime": TARGET_RUNTIME,
            "kernel": TARGET_KERNEL,
        },
        "target_verified": True,
        "partition": {**asdict(partition), "start_sector": start_sector},
        "transition": {
            "partition_offset": f"0x{PARAM_DEBUG_OFFSET:06x}",
            "size": 4,
            "before_label": transition.before_label,
            "after_label": transition.after_label,
            "before_bytes_hex": transition.before_bytes.hex(),
            "after_bytes_hex": transition.after_bytes.hex(),
            "before_sha256": transition.before_sha256,
            "after_sha256": transition.after_sha256,
            "before_stable_sha256": transition.before_stable_sha256,
            "after_stable_sha256": transition.after_stable_sha256,
            "stable_mask": {
                "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
                "stable_ranges": [list(PARAM_STABLE_RANGE)],
                "stable_size": PARAM_STABLE_SIZE,
            },
        },
        "cmdline_before": cmdline,
        "download_mode_before": dload,
        "stophud": stophud,
        "stophud_frames": stophud_frames,
        "bridge_binding": dict(bridge_binding),
        "effect_consumption_claim": None,
        "effect_consumption_claim_path": None,
    }
    _atomic_replace_json(journal_path, journal)

    payload_record: dict[str, object] | None = None
    smoke_record: dict[str, object] | None = None
    before_hash: str | None = None
    after_hash: str | None = None
    before_stable_hash: str | None = None
    after_stable_hash: str | None = None
    before_capture: dict[str, object] | None = None
    after_capture: dict[str, object] | None = None
    effect_frame = None
    effect_claim: dict[str, object] | None = None
    effect_claim_blocked = False
    effect_armed = False
    cleanup_binding_failed = False
    mutation_binding_failed = False

    def defer_cleanup(reason: str) -> None:
        """Retain host-only cleanup deferral without touching the bridge."""

        if journal.get("status") in {"APPLIED_VERIFIED", "RESTORED_VERIFIED"}:
            journal["status"] = "CLEANUP_DEFERRED_RECONCILE_REQUIRED"
        journal["cleanup_deferred"] = True
        journal["reconcile_required"] = True
        journal["cleanup_deferred_reason"] = reason
        _atomic_replace_json(journal_path, journal)

    def fresh_binding(label: str):
        """Require the exact original bridge immediately before a mutation."""

        nonlocal mutation_binding_failed
        if bridge_binding is None:
            reason = f"{label}: initial bridge binding is unavailable"
            mutation_binding_failed = True
            defer_cleanup(reason)
            raise RuntimeError(reason)
        try:
            current = revalidate_bridge_binding(bridge_binding)
        except BaseException as exc:
            reason = f"{label}: {type(exc).__name__}: {exc}"
            mutation_binding_failed = True
            if not effect_armed and journal.get("status") == "PREFLIGHT":
                journal["status"] = "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
            defer_cleanup(reason)
            raise
        if not isinstance(current, Mapping) or not _bridge_bindings_match(
            bridge_binding, current
        ):
            reason = f"{label}: bridge binding drifted"
            mutation_binding_failed = True
            if not effect_armed and journal.get("status") == "PREFLIGHT":
                journal["status"] = "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
            defer_cleanup(reason)
            raise RuntimeError(reason)
        return current

    try:
        _invoke_with_binding(
            create_and_validate_node,
            (args.host, args.port, partition, args.command_timeout),
            fresh_binding,
            "node_create_group",
        )
        # The full image is obtained through the bounded binary exchange, not
        # only through a device-side digest.  Eligibility is keyed to the
        # stable mask so an observed boot-cycle byte-0 variant remains valid;
        # no ownership of that volatile byte is inferred here.
        fresh_binding("transition_before_capture")
        before_capture = _capture_exact_param_image(
            args.host,
            args.port,
            partition,
            args.capture_timeout,
            "transition_before",
        )
        before_hash = str(before_capture["full_sha256"])
        before_stable_hash = str(before_capture["stable_sha256"])
        before_live_fields = before_capture["decoded_fields"]
        if not isinstance(before_live_fields, Mapping):
            raise ValueError("transition before capture lacks decoded fields")
        journal.update(
            {
                "device_sha256_before": before_hash,
                "device_stable_sha256_before": before_stable_hash,
                "stable_mask": {
                    "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
                    "stable_ranges": [list(PARAM_STABLE_RANGE)],
                    "stable_size": PARAM_STABLE_SIZE,
                },
                "stable_range_before": before_capture["stable_range"],
                "stable_range": before_capture["stable_range"],
                "volatile_byte0_before": before_capture["volatile_byte0"],
                "observed_boot_cycle_volatile_byte0_before": before_capture[
                    "volatile_byte0"
                ],
                "decoded_fields_before": before_live_fields,
            }
        )
        if before_stable_hash != transition.before_stable_sha256:
            journal["status"] = "REFUSED_BEFORE_EFFECT_STABLE_HASH_MISMATCH"
            _atomic_replace_json(journal_path, journal)
            raise ValueError(
                f"live stable param SHA-256 {before_stable_hash} != required {transition.before_stable_sha256}"
            )
        if type(before_capture["volatile_byte0"]) is not int:
            raise ValueError("transition before byte-0 observation is malformed")
        if before_live_fields["debuglevel"]["label"] != transition.before_label:
            raise ValueError("live before debug label does not match stable transition")
        for name in ("force_upload_flag", "FMM_lock", "dump_sink"):
            if before_live_fields[name]["value"] != before_fields[name]["value"]:
                raise ValueError(f"live before non-debug field changed: {name}")

        payload_record = _invoke_with_binding(
            _write_ascii_payload,
            (
                args.host,
                args.port,
                PAYLOAD_PATH,
                transition.after_bytes,
                args.command_timeout,
            ),
            fresh_binding,
            "param_payload_group",
        )
        smoke_record = _invoke_with_binding(
            verify_regular_file_dd,
            (
                args.host,
                args.port,
                PAYLOAD_PATH,
                transition.after_bytes,
                args.command_timeout,
            ),
            fresh_binding,
            "smoke_group",
        )
        # Verify the exact target and staged bytes once before arming.  The
        # same proof is repeated after the durable marker, immediately before
        # the sole dd, so a node/payload swap after the smoke cannot pass.
        fresh_binding("pre_effect_target")
        pre_effect_target = verify_exact_param_target(
            args.host,
            args.port,
            partition,
            start_sector,
            PAYLOAD_PATH,
            transition.after_bytes,
            args.command_timeout,
            expected_record=payload_record,
            evidence_prefix="pre_effect_target",
        )
        dd_args = fixed_dd_args(PAYLOAD_PATH, partition.node_path)
        # Claim the semantic transition immediately before its durable marker.
        # A second owner with a different experiment ID but the same exact
        # preimage/action/geometry must stop here and never dispatch dd.
        effect_claim_path = _effect_claim_path(
            transition.action, before_stable_hash, partition, start_sector
        )
        journal["effect_consumption_claim_path"] = effect_claim_path.name
        try:
            effect_claim = _claim_effect_consumption(
                transition.action,
                before_stable_hash,
                partition,
                start_sector,
                args.experiment_id,
                full_preimage_hash=before_hash,
            )
        except BaseException as claim_exc:
            # An existing or partially-created claim is a no-replay owner
            # boundary.  Do not clean shared fixed remote objects through this
            # losing owner; the winner may be in its staging/effect sequence.
            effect_claim_blocked = effect_claim_path.exists() or effect_claim_path.is_symlink()
            if effect_claim_blocked:
                effect_claim = _effect_claim_stub(
                    effect_claim_path,
                    _effect_claim_key(
                        transition.action, before_stable_hash, partition, start_sector
                    ),
                    transition.action,
                    before_stable_hash,
                    partition,
                    start_sector,
                    args.experiment_id,
                )
                journal["effect_consumption_claim"] = effect_claim
            journal["status"] = "PRE_EFFECT_EFFECT_CLAIM_FAILED"
            journal["error"] = f"{type(claim_exc).__name__}: {claim_exc}"
            _atomic_replace_json(journal_path, journal)
            raise
        if isinstance(effect_claim, Mapping):
            effect_claim = dict(effect_claim)
            effect_claim.update(
                {
                    "preimage_full_sha256": before_hash,
                    "stable_preimage_sha256": before_stable_hash,
                    "stable_mask": {
                        "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
                        "stable_ranges": [list(PARAM_STABLE_RANGE)],
                        "stable_size": PARAM_STABLE_SIZE,
                    },
                }
            )
        journal["effect_consumption_claim"] = effect_claim
        journal.update(
            {
                "pre_effect_target_verification": pre_effect_target,
                "payload": payload_record,
                "regular_file_dd_smoke": smoke_record,
                "effect_argv": ["run", "/bin/toybox", *dd_args],
            }
        )
        _atomic_replace_json(journal_path, journal)
        # This is the durable one-shot effect marker.  From this point any
        # verifier/binding/transport failure is ambiguous and no cleanup or
        # replay may occur.
        journal.update(
            {
                "status": "EFFECT_DISPATCH_STARTED",
                "effect_dispatched": True,
                "effect_armed": True,
                "effect_dispatched_count": 1,
                "write_count": 1,
                "partition_writes": True,
            }
        )
        # Treat the arm as potentially durable before attempting the fsync /
        # replace itself.  A host exception after os.replace cannot prove that
        # the marker was absent, so the conservative branch must forbid
        # cleanup and replay.
        effect_armed = True
        _atomic_replace_json(journal_path, journal)

        fresh_binding("post_marker_target")
        post_effect_target = verify_exact_param_target(
            args.host,
            args.port,
            partition,
            start_sector,
            PAYLOAD_PATH,
            transition.after_bytes,
            args.command_timeout,
            expected_record=payload_record,
            evidence_prefix="post_marker_target",
        )
        journal["post_marker_target_verification"] = post_effect_target
        if bridge_binding is None:
            raise ValueError("effect arm lacks initial bridge binding")
        # No journal fsync, host filesystem command, or unrelated device
        # operation may occur after this final exact rebind and before dd.
        final_bridge_binding = revalidate_bridge_binding(bridge_binding)
        if not isinstance(final_bridge_binding, Mapping) or not _bridge_bindings_match(
            bridge_binding, final_bridge_binding
        ):
            raise RuntimeError("bridge binding drifted immediately before param effect")
        journal["final_effect_bridge_binding"] = dict(final_bridge_binding)

        effect_frame = exchange(
            args.host,
            args.port,
            Command("param_debug_transition", ("run", "/bin/toybox", *dd_args)),
            args.effect_timeout,
            allow_error=True,
        )
        journal["effect_receipt"] = {
            "begin": effect_frame.begin,
            "end": effect_frame.end,
            "payload_base64": base64.b64encode(effect_frame.payload).decode("ascii"),
            "transcript_sha256": sha256(effect_frame.transcript),
        }
        journal["status"] = "EFFECT_RETURNED_VERIFYING_FULL_HASH"
        _atomic_replace_json(journal_path, journal)

        # Capture the complete post-effect image through the same bounded
        # binary path and exact node binding.  The full digest is retained as
        # an observation; stable eligibility intentionally ignores byte 0.
        fresh_binding("transition_after_capture")
        after_capture = _capture_exact_param_image(
            args.host,
            args.port,
            partition,
            args.capture_timeout,
            "transition_after",
        )
        after_hash = str(after_capture["full_sha256"])
        after_stable_hash = str(after_capture["stable_sha256"])
        after_live_fields = after_capture["decoded_fields"]
        if not isinstance(after_live_fields, Mapping):
            raise ValueError("transition after capture lacks decoded fields")
        journal.update(
            {
                "device_sha256_after": after_hash,
                "device_stable_sha256_after": after_stable_hash,
                "stable_range_after": after_capture["stable_range"],
                "volatile_byte0_after": after_capture["volatile_byte0"],
                "observed_boot_cycle_volatile_byte0_after": after_capture[
                    "volatile_byte0"
                ],
                "decoded_fields_after": after_live_fields,
            }
        )
        rc_ok = int(effect_frame.end["rc"], 0) == 0 and effect_frame.end["status"] == "ok"
        hash_ok = after_stable_hash == transition.after_stable_sha256
        byte0_ok = (
            before_capture is not None
            and after_capture["volatile_byte0"] == before_capture["volatile_byte0"]
        )
        fields_ok = after_live_fields["debuglevel"]["label"] == transition.after_label
        for name in ("force_upload_flag", "FMM_lock", "dump_sink"):
            fields_ok = fields_ok and (
                after_live_fields[name]["value"] == before_fields[name]["value"]
            )
        if not rc_ok or not hash_ok or not byte0_ok or not fields_ok:
            journal["status"] = (
                "NO_EFFECT_REPLAY_FORBIDDEN"
                if after_stable_hash == transition.before_stable_sha256
                else "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
            )
            _atomic_replace_json(journal_path, journal)
            raise RuntimeError(
                f"transition verification failed: rc_ok={rc_ok} stable_ok={hash_ok} "
                f"byte0_ok={byte0_ok} fields_ok={fields_ok} after={after_hash}; "
                "effect was dispatched once and will not be replayed"
            )
        journal["status"] = "APPLIED_VERIFIED" if args.action == "apply-mid" else "RESTORED_VERIFIED"
        journal["reconcile_required"] = False
        journal["cleanup_deferred"] = False
        journal["completed_utc"] = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat()
        _atomic_replace_json(journal_path, journal)
    except BaseException as exc:
        if effect_armed:
            if journal.get("status") in {
                "EFFECT_DISPATCH_STARTED",
                "EFFECT_RETURNED_VERIFYING_FULL_HASH",
            }:
                journal["status"] = "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
            journal["error"] = f"{type(exc).__name__}: {exc}"
            journal["cleanup_deferred"] = True
            journal["reconcile_required"] = True
            _atomic_replace_json(journal_path, journal)
        else:
            # Any exception before the durable effect marker is a pre-effect
            # incident.  Publish the corrected state before the public
            # incident manifest so the private journal cannot remain at the
            # optimistic PREFLIGHT status with a null error.
            journal.update(
                {
                    "status": "PRE_EFFECT_PREFLIGHT_INCOMPLETE",
                    "error": f"{type(exc).__name__}: {exc}",
                    "effect_dispatched": False,
                    "effect_dispatched_count": 0,
                    "write_count": 0,
                    "partition_writes": False,
                }
            )
            _atomic_replace_json(journal_path, journal)
        publish_incident(exc)
        raise
    finally:
        cleanup_allowed = journal.get("status") in {
            "APPLIED_VERIFIED",
            "RESTORED_VERIFIED",
        }
        if effect_claim_blocked:
            # A losing owner must not remove the shared fixed node/payload
            # while the claim winner may still be staging or dispatching.
            defer_cleanup("semantic effect claim was already owned or partially created")
        elif effect_armed and not cleanup_allowed:
            # An effect marker is a no-replay boundary.  Preserve host-side
            # reconciliation evidence and send zero cleanup/device commands.
            defer_cleanup("effect outcome is ambiguous or unverified")
        elif cleanup_binding_failed:
            # The final pre-effect bridge check failed.  Do not issue cleanup
            # through the bridge whose identity was just rejected.
            defer_cleanup("bridge binding failed before effect arm")
        elif mutation_binding_failed:
            # A failed pre-effect mutation-group revalidation is a hard stop;
            # do not issue any later cleanup command on a bridge whose
            # continuity was not proved.
            defer_cleanup("bridge binding failed before a mutation group")
        elif not effect_armed:
            # For an ordinary pre-effect failure, require a fresh matching
            # host-only bridge binding immediately before cleanup.  If that
            # check fails, defer rather than sending an unbound command.
            try:
                if bridge_binding is None:
                    raise RuntimeError("cleanup lacks initial bridge binding")
                cleanup_binding = revalidate_bridge_binding(bridge_binding)
                if not isinstance(cleanup_binding, Mapping) or not _bridge_bindings_match(
                    bridge_binding, cleanup_binding
                ):
                    raise RuntimeError("bridge binding drifted before cleanup")
            except BaseException as cleanup_exc:
                defer_cleanup(
                    f"pre-effect cleanup bridge binding failed: "
                    f"{type(cleanup_exc).__name__}: {cleanup_exc}"
                )
            else:
                cleanup_allowed = True

        if cleanup_allowed and not cleanup_binding_failed and not (
            effect_armed and journal.get("status") not in {"APPLIED_VERIFIED", "RESTORED_VERIFIED"}
        ):
            try:
                # This durable marker precedes every terminal pre-effect (or
                # post-success) cleanup command.  If a later command fails,
                # the journal remains conservative and records that cleanup
                # was attempted but not proved complete.
                journal["cleanup_attempted"] = True
                journal["cleanup_completed"] = False
                journal["node_cleanup_verified"] = False
                _atomic_replace_json(journal_path, journal)
                _invoke_with_binding(
                    _remove_temp,
                    (
                        args.host,
                        args.port,
                        PAYLOAD_PATH,
                        args.command_timeout,
                        "payload_cleanup_after",
                    ),
                    fresh_binding,
                    "payload_cleanup_after",
                )
                _invoke_with_binding(
                    _remove_temp,
                    (
                        args.host,
                        args.port,
                        SMOKE_PATH,
                        args.command_timeout,
                        "smoke_cleanup_final",
                    ),
                    fresh_binding,
                    "smoke_cleanup_final",
                )
                _invoke_with_binding(
                    remove_node,
                    (args.host, args.port, partition, args.command_timeout),
                    fresh_binding,
                    "node_cleanup_final",
                )
                journal["cleanup_completed"] = True
                journal["node_cleanup_verified"] = True
                journal["cleanup_deferred"] = False
                journal["reconcile_required"] = False
                _atomic_replace_json(journal_path, journal)
            except BaseException as cleanup_exc:
                defer_cleanup(
                    f"successful cleanup was not proved: "
                    f"{type(cleanup_exc).__name__}: {cleanup_exc}"
                )
                publish_incident(cleanup_exc)
                raise

    completed = str(journal["completed_utc"])
    manifest = {
        "schema": "sdm855-a90-param-debug-transition-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "stophud_accepted": bool(stophud.get("accepted")),
        "stophud_busy_retries": stophud.get("busy_retries", 0),
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": TARGET_RUNTIME,
        "action": transition.action,
        "classification": journal["status"],
        "partition": {**asdict(partition), "start_sector": start_sector},
        "transition": journal["transition"],
        "device_sha256_before": before_hash,
        "device_sha256_after": after_hash,
        "device_stable_sha256_before": before_stable_hash,
        "device_stable_sha256_after": after_stable_hash,
        "stable_mask": journal.get("stable_mask"),
        "volatile_byte0_before": journal.get("volatile_byte0_before"),
        "volatile_byte0_after": journal.get("volatile_byte0_after"),
        "observed_boot_cycle_volatile_byte0_before": journal.get(
            "volatile_byte0_before"
        ),
        "observed_boot_cycle_volatile_byte0_after": journal.get(
            "volatile_byte0_after"
        ),
        "full_hash_observed": True,
        "full_hash_verified": after_hash == transition.after_sha256,
        "stable_hash_verified": after_stable_hash == transition.after_stable_sha256,
        "effect_dispatched_count": 1,
        "write_count": journal.get("write_count", 1),
        "partition_writes": journal.get("partition_writes", True),
        "effect_replayed": False,
        "effect_consumption_claim": _public_effect_claim(
            journal.get("effect_consumption_claim")
        ),
        "effect_consumption_claim_path": journal.get("effect_consumption_claim_path"),
        "effect_a90p1_end": effect_frame.end if effect_frame else None,
        "payload": {
            "size": payload_record["size"],
            "sha256": payload_record["sha256"],
        },
        "regular_file_dd_smoke": smoke_record,
        "cmdline_before_reboot": {
            "androidboot.debug_level": cmdline.get("androidboot.debug_level"),
            "androidboot.force_upload": cmdline.get("androidboot.force_upload"),
            "sec_debug.dump_sink": cmdline.get("sec_debug.dump_sink"),
        },
        "download_mode_before": dload,
        "device_rebooted": False,
        "claims": {
            "PROVED": [
                "Exactly one four-byte bounded write effect was dispatched to the exact live param partition and the post-write stable hash matched the host-derived expected image.",
                "force_upload_flag, FMM_lock and dump_sink are unchanged in the host-derived before/after images whose stable SHA-256 values bind the live transition; full hashes remain forensic observations.",
            ],
            "UNKNOWN": [
                "The current boot still reflects the pre-transition XBL cmdline until a separate normal reboot consumes the persistent field.",
            ],
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return journal_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--action", required=True, choices=tuple(TRANSITIONS))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--command-timeout", type=float, default=45.0)
    parser.add_argument("--hash-timeout", type=float, default=90.0)
    parser.add_argument("--capture-timeout", type=float, default=180.0)
    parser.add_argument("--effect-timeout", type=float, default=45.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    journal, manifest = execute(args)
    print(f"journal: {journal}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
