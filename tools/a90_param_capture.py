#!/usr/bin/env python3
"""Capture the exact A90 ``param`` partition as a rollback artifact.

This collector is deliberately narrower than the firmware collector.  It only
accepts the operator-pinned loopback A90P1 bridge, requires the exact live
SM-A908N runtime identity, resolves exactly ``sda10``/``PARTNAME=param``, and
captures exactly 10 MiB.  The target is hashed before and after the transfer;
the host copy must match both hashes.  No partition data is written.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import struct
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from tools.a90_autohud_arbitration import run_stophud
    from tools.a90_pa28_live import revalidate_bridge_binding, validate_bridge_binding
    from tools.a90_partition_capture import (
        Partition,
        binary_exchange,
        create_and_validate_node,
        device_sha256,
        fsync_directory,
        parse_decimal,
        parse_uevent,
        remove_node,
        sha256,
        text_exchange,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new  # type: ignore
    from a90_autohud_arbitration import run_stophud  # type: ignore
    from a90_pa28_live import (  # type: ignore
        revalidate_bridge_binding,
        validate_bridge_binding,
    )
    from a90_partition_capture import (  # type: ignore
        Partition,
        binary_exchange,
        create_and_validate_node,
        device_sha256,
        fsync_directory,
        parse_decimal,
        parse_uevent,
        remove_node,
        sha256,
        text_exchange,
    )


# Persistent capture artifacts are always rooted in this repository.  The
# module attribute is an explicit host-test seam; the CLI has no output-root
# option and callers cannot select a different artifact namespace.
REPO_ROOT = Path(__file__).resolve().parents[1]

SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
# ``/proc/cmdline`` is an ASCII token stream.  Keys are strict tokens and
# values are nonempty printable tokens (embedded ``=`` is valid in values such
# as ``root=PARTUUID=...``); no whitespace/control/NUL can alter tokenization.
CMDLINE_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]+\Z")
# Values may contain ``=`` (for example ``root=PARTUUID=...`` and the
# framebuffer ``video=...,bpp=32`` token), but must begin with a non-separator
# byte and contain no whitespace/control/NUL.
CMDLINE_VALUE_RE = re.compile(r"[^=\x00-\x20\x7f][^\x00-\x20\x7f]*\Z")
KNOWN_BARE_FLAGS = frozenset({"skip_initramfs", "rootwait", "ro"})

TARGET_MODEL = "SM-A908N"
TARGET_SOC = "SM8150"
TARGET_BOOTLOADER = "A908NKSU5EWA3"
TARGET_RUNTIME = "v2321-usb-clean-identity-rodata"
TARGET_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
TARGET_RUNTIME_LINE = f"A90 Linux init 0.9.285 ({TARGET_RUNTIME})"
RUNTIME_METADATA_LINE_RE = re.compile(
    r"display: [0-9]+x[0-9]+"
    r"(?: connector=[0-9]+)?(?: crtc=[0-9]+)?(?: fb=[0-9]+)?\Z"
)

PARAM_DEVNAME = "sda10"
PARAM_PARTNAME = "param"
PARAM_MAJOR = 8
PARAM_MINOR = 10
PARAM_PARTITION_BYTES = 0xA00000
PARAM_SECTORS = PARAM_PARTITION_BYTES // 512
PARAM_START_SECTOR = 125080
PARAM_READ_ONLY = 0
PARAM_LOGICAL_BLOCK_SIZE = 4096
PARAM_CMDLINE_UPLOAD_OFFSET = "9438196"
PARAM_RECORD_OFFSET = PARAM_PARTITION_BYTES - 0x100000
PARAM_DEBUG_OFFSET = PARAM_RECORD_OFFSET + 0x000
PARAM_FORCE_UPLOAD_OFFSET = PARAM_RECORD_OFFSET + 0x3F4
PARAM_FMM_LOCK_OFFSET = PARAM_RECORD_OFFSET + 0x3FC
PARAM_DUMP_SINK_OFFSET = PARAM_RECORD_OFFSET + 0x400

# The first byte of the retained 10 MiB image is an observed boot-cycle
# volatile byte (the live post-boot image changed only here).  Its ownership is
# intentionally not inferred.  Every stable eligibility decision therefore
# hashes the exact half-open range [1, 0xA00000)
# while retaining the full image/hash for transfer and forensic evidence.
PARAM_VOLATILE_RANGES = ((0, 1),)
PARAM_STABLE_EXCLUDED_RANGES = PARAM_VOLATILE_RANGES
PARAM_STABLE_RANGE = (1, PARAM_PARTITION_BYTES)
PARAM_STABLE_RANGES = (PARAM_STABLE_RANGE,)
PARAM_STABLE_OFFSET = PARAM_STABLE_RANGE[0]
PARAM_STABLE_END = PARAM_STABLE_RANGE[1]
PARAM_STABLE_SIZE = PARAM_STABLE_END - PARAM_STABLE_OFFSET
PARAM_STABLE_MASK = {
    "excluded_ranges": [[0, 1]],
    "stable_ranges": [[1, PARAM_PARTITION_BYTES]],
    "stable_size": PARAM_STABLE_SIZE,
}

PARAM_LOW_FULL_SHA256 = (
    "1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345"
)
PARAM_MID_FULL_SHA256 = (
    "50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256"
)
PARAM_STABLE_LOW_SHA256 = (
    "c0c7147418cf13145a44369a960c81647d347f317cb35baed1d85b286253c68a"
)
PARAM_STABLE_MID_SHA256 = (
    "9b85da06e4e4b1adb330c7169049a313ee5b0aa68014a2915a470f034c08f53f"
)
# Descriptive aliases used by the transition/recovery owners and embedders.
STABLE_PARAM_OFFSET = PARAM_STABLE_OFFSET
STABLE_PARAM_SIZE = PARAM_STABLE_SIZE
STABLE_PARAM_RANGE = PARAM_STABLE_RANGE
STABLE_PARAM_MASK = PARAM_STABLE_MASK
STABLE_MASK = PARAM_STABLE_MASK
VOLATILE_RANGES = PARAM_VOLATILE_RANGES
STABLE_RANGES = PARAM_STABLE_RANGES
STABLE_LOW_SHA256 = PARAM_STABLE_LOW_SHA256
STABLE_MID_SHA256 = PARAM_STABLE_MID_SHA256
LOW_STABLE_SHA256 = PARAM_STABLE_LOW_SHA256
MID_STABLE_SHA256 = PARAM_STABLE_MID_SHA256

KERNEL_DEBUG_LOW = 0x574F4C44
KERNEL_DEBUG_MID = 0x44494D44
KERNEL_DEBUG_HIGH = 0x47494844
FMM_LOCK_MAGIC = 0x464D4F4E
DUMP_SINK_SDCARD = 0x73646364
DUMP_SINK_BOOTDEV = 0x42544456

FIELD_OFFSETS = {
    "debuglevel": PARAM_DEBUG_OFFSET,
    "force_upload_flag": PARAM_FORCE_UPLOAD_OFFSET,
    "FMM_lock": PARAM_FMM_LOCK_OFFSET,
    "dump_sink": PARAM_DUMP_SINK_OFFSET,
}

MAX_COMMAND_TIMEOUT = 120.0
MAX_CAPTURE_TIMEOUT = 600.0


def _atomic_replace_json(path: Path, value: object, mode: int = 0o600) -> None:
    """Durably retain lifecycle/arbitration evidence on every attempt."""

    data = json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError(f"journal temporary already exists: {temporary}")
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


def _bridge_bindings_match(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    """Compare exact bridge identity while ignoring validation timestamp."""

    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def parse_cmdline(payload: bytes) -> dict[str, str]:
    if type(payload) is not bytes:
        raise ValueError("cmdline payload must be bytes")
    if b"\x00" in payload:
        raise ValueError("cmdline contains NUL")
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("cmdline is not strict ASCII") from exc
    # The native cat receipt leaves the proc file's one terminal LF in the
    # payload.  Strip exactly that framing byte (and an optional CR paired
    # with it); all other leading/trailing or repeated whitespace is invalid.
    if text.endswith("\n"):
        text = text[:-1]
        if text.endswith("\r"):
            text = text[:-1]
    if not text or text[0].isspace() or text[-1].isspace():
        raise ValueError("cmdline is empty or has invalid surrounding whitespace")
    tokens = text.split(" ")
    if any(token == "" for token in tokens):
        raise ValueError("cmdline contains repeated or non-space whitespace")
    result: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            if token not in KNOWN_BARE_FLAGS:
                raise ValueError(f"unknown bare cmdline flag: {token!r}")
            key = token
            value = ""
        else:
            key, value = token.split("=", 1)
            if CMDLINE_KEY_RE.fullmatch(key) is None:
                raise ValueError(f"malformed cmdline key: {key!r}")
            if CMDLINE_VALUE_RE.fullmatch(value) is None:
                raise ValueError(f"malformed cmdline value for {key!r}")
        if key in result:
            raise ValueError(f"duplicate cmdline key: {key}")
        result[key] = value
    if not result:
        raise ValueError("cmdline contains no tokens")
    return result


def validate_runtime(version_payload: bytes, cmdline: dict[str, str]) -> None:
    if type(version_payload) is not bytes:
        raise ValueError("runtime version payload must be bytes")
    try:
        version = version_payload.decode("ascii", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ValueError("runtime version payload is not strict ASCII") from exc
    if "\x00" in version:
        raise ValueError("runtime version payload contains NUL")
    if version.endswith("\n"):
        version = version[:-1]
    lines = version.split("\n")
    if any(not line for line in lines):
        raise ValueError("A90 runtime identity contains an empty line")
    expected_build = f"version: 0.9.285 build={TARGET_RUNTIME}"
    expected_kernel = f"kernel: {TARGET_KERNEL}"
    # The native V2321 ``version`` command also emits owner/display metadata.
    # Identity is still strict: each recognized identity prefix must occur
    # exactly once, and its complete line must equal the pinned value.  Other
    # metadata lines are retained as opaque context rather than accepted as a
    # substitute for the exact version/build/kernel lines.
    runtime_lines = [line for line in lines if line.startswith("A90 Linux init ")]
    build_lines = [line for line in lines if line.startswith("version: ")]
    kernel_lines = [line for line in lines if line.startswith("kernel: ")]
    for line in lines:
        if any(marker in line for marker in ("A90 Linux init ", "version: ", "kernel: ")):
            if not line.startswith(("A90 Linux init ", "version: ", "kernel: ")):
                raise ValueError("A90 runtime identity marker is malformed")
        elif line != "made by device owner" and RUNTIME_METADATA_LINE_RE.fullmatch(line) is None:
            raise ValueError("A90 runtime metadata line is not exact")
    if runtime_lines not in ([], [TARGET_RUNTIME_LINE]):
        raise ValueError("A90 runtime banner is not exact")
    if build_lines != [expected_build]:
        raise ValueError("A90 version/build identity is not exact")
    if kernel_lines != [expected_kernel]:
        raise ValueError("A90 kernel identity is not exact")
    identity_order = [
        line
        for line in lines
        if line.startswith(("A90 Linux init ", "version: ", "kernel: "))
    ]
    expected_order = (
        [TARGET_RUNTIME_LINE, expected_build, expected_kernel]
        if runtime_lines
        else [expected_build, expected_kernel]
    )
    if identity_order != expected_order:
        raise ValueError("A90 runtime identity lines are out of order")
    if not isinstance(cmdline, dict) or any(
        type(key) is not str or type(value) is not str
        for key, value in cmdline.items()
    ):
        raise ValueError("live cmdline identity is not a strict string mapping")
    for key, value in cmdline.items():
        if key in KNOWN_BARE_FLAGS:
            if value != "":
                raise ValueError(f"known bare cmdline flag has a value: {key!r}")
            continue
        if CMDLINE_KEY_RE.fullmatch(key) is None or CMDLINE_VALUE_RE.fullmatch(value) is None:
            raise ValueError(f"live cmdline key/value is not strict: {key!r}")
    if cmdline.get("androidboot.em.model") != TARGET_MODEL:
        raise ValueError("live cmdline is not bound to SM-A908N")
    if cmdline.get("androidboot.bootloader") != TARGET_BOOTLOADER:
        raise ValueError("live bootloader build differs from the exact target")


def validate_param_capture_cmdline(cmdline: Mapping[str, str]) -> None:
    """Require the exact LOW capture cmdline safety contract."""

    if not isinstance(cmdline, Mapping) or any(
        type(key) is not str or type(value) is not str
        for key, value in cmdline.items()
    ):
        raise ValueError("param capture cmdline is not a strict string mapping")
    expected = {
        "androidboot.em.model": TARGET_MODEL,
        "androidboot.bootloader": TARGET_BOOTLOADER,
        "androidboot.debug_level": "0x4f4c",
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
        "androidboot.upload_offset": PARAM_CMDLINE_UPLOAD_OFFSET,
    }
    for key, expected_value in expected.items():
        if cmdline.get(key) != expected_value:
            raise ValueError(
                f"param capture cmdline {key} is not exact: "
                f"{cmdline.get(key)!r} != {expected_value!r}"
            )


def discover_param(host: str, port: int, timeout: float) -> tuple[Partition, int]:
    prefix = f"/sys/class/block/{PARAM_DEVNAME}"
    uevent = parse_uevent(
        text_exchange(host, port, "param_uevent", ("cat", f"{prefix}/uevent"), timeout)
    )
    required = {
        "DEVNAME": PARAM_DEVNAME,
        "DEVTYPE": "partition",
        "PARTNAME": PARAM_PARTNAME,
        "PARTN": "10",
        "MAJOR": str(PARAM_MAJOR),
        "MINOR": str(PARAM_MINOR),
    }
    if any(uevent.get(key) != value for key, value in required.items()):
        raise ValueError(f"exact param identity mismatch: {uevent}")

    sectors = parse_decimal(
        text_exchange(host, port, "param_size", ("cat", f"{prefix}/size"), timeout),
        "param sectors",
    )
    read_only = parse_decimal(
        text_exchange(host, port, "param_ro", ("cat", f"{prefix}/ro"), timeout),
        "param read-only flag",
    )
    start_sector = parse_decimal(
        text_exchange(host, port, "param_start", ("cat", f"{prefix}/start"), timeout),
        "param start sector",
    )
    logical_block_size = parse_decimal(
        text_exchange(
            host,
            port,
            "sda_logical_block_size",
            ("cat", "/sys/class/block/sda/queue/logical_block_size"),
            timeout,
        ),
        "sda logical block size",
    )
    partition = Partition(
        partname=uevent["PARTNAME"],
        devname=uevent["DEVNAME"],
        major=int(uevent["MAJOR"], 10),
        minor=int(uevent["MINOR"], 10),
        sectors=sectors,
        byte_size=sectors * 512,
        read_only=read_only,
        logical_block_size=logical_block_size,
    )
    validate_param_partition(partition, start_sector)
    return partition, start_sector


def validate_param_partition(partition: Partition, start_sector: int) -> None:
    if type(start_sector) is not int:
        raise ValueError("param start sector is not an exact integer")
    expected_types = {
        "partname": str,
        "devname": str,
        "major": int,
        "minor": int,
        "sectors": int,
        "byte_size": int,
        "read_only": int,
        "logical_block_size": int,
    }
    if any(type(getattr(partition, key)) is not kind for key, kind in expected_types.items()):
        raise ValueError("param geometry contains a non-exact scalar type")
    if partition.partname != PARAM_PARTNAME or partition.devname != PARAM_DEVNAME:
        raise ValueError("partition is not exact sda10/PARTNAME=param")
    if (partition.major, partition.minor) != (PARAM_MAJOR, PARAM_MINOR):
        raise ValueError("param major/minor differs from the exact live binding")
    if partition.sectors != PARAM_SECTORS or partition.byte_size != PARAM_PARTITION_BYTES:
        raise ValueError("param partition is not exactly 10 MiB")
    if partition.read_only != PARAM_READ_ONLY:
        raise ValueError("param live sysfs read-only state changed from zero")
    if partition.logical_block_size != PARAM_LOGICAL_BLOCK_SIZE:
        raise ValueError("param parent logical block size is not 4096")
    if start_sector != PARAM_START_SECTOR:
        raise ValueError(
            f"param start sector is not the exact pinned value {PARAM_START_SECTOR}"
        )


def decode_fields(data: bytes) -> dict[str, object]:
    if type(data) is not bytes:
        raise ValueError("param image must be bytes")
    if len(data) != PARAM_PARTITION_BYTES:
        raise ValueError(f"param image size {len(data)} != {PARAM_PARTITION_BYTES}")
    values = {
        name: struct.unpack_from("<I", data, offset)[0]
        for name, offset in FIELD_OFFSETS.items()
    }
    debug_labels = {
        KERNEL_DEBUG_LOW: "LOW",
        KERNEL_DEBUG_MID: "MID",
        KERNEL_DEBUG_HIGH: "HIGH",
    }
    sink_labels = {
        0: "USB_DEFAULT",
        DUMP_SINK_SDCARD: "SDCARD",
        DUMP_SINK_BOOTDEV: "BOOTDEV_INTERNAL",
    }
    return {
        name: {
            "partition_offset": f"0x{FIELD_OFFSETS[name]:06x}",
            "record_offset": f"0x{FIELD_OFFSETS[name] - PARAM_RECORD_OFFSET:03x}",
            "value": f"0x{value:08x}",
            "label": (
                debug_labels.get(value, "UNKNOWN")
                if name == "debuglevel"
                else ("LOCKED" if value == FMM_LOCK_MAGIC else "NOT_LOCK_MAGIC")
                if name == "FMM_lock"
                else sink_labels.get(value, "USB_DEFAULT_BRANCH_OTHER")
                if name == "dump_sink"
                else "ENABLED" if value == 5 else "NOT_ENABLED_VALUE_5"
            ),
        }
        for name, value in values.items()
    }


def stable_param_sha256(data: bytes) -> str:
    """Hash the contract-selected stable param bytes using the fixed mask.

    The contract is intentionally strict: callers must provide the complete
    10 MiB image, and the sole excluded range is byte ``[0, 1)``.  A partial
    read, a text value, or a caller-selected range is never a stable identity.
    """

    if type(data) is not bytes:
        raise ValueError("stable param hash input must be bytes")
    if len(data) != PARAM_PARTITION_BYTES:
        raise ValueError(
            f"stable param hash requires exactly {PARAM_PARTITION_BYTES} bytes"
        )
    return hashlib.sha256(data[PARAM_STABLE_OFFSET:PARAM_STABLE_END]).hexdigest()


# Explicit alias for code that spells the operation as an image hash.
stable_param_image_sha256 = stable_param_sha256


def stable_param_mask() -> dict[str, object]:
    """Return a fresh copy of the fixed stable/volatile range contract."""

    return {
        "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
        "stable_ranges": [list(item) for item in PARAM_STABLE_RANGES],
        "stable_size": PARAM_STABLE_SIZE,
    }


def stable_param_evidence(data: bytes) -> dict[str, object]:
    """Return exact stable/full observations for one complete image."""

    fields = decode_fields(data)
    full_hash = hashlib.sha256(data).hexdigest()
    stable_hash = stable_param_sha256(data)
    return {
        "size": len(data),
        "sha256": full_hash,
        "full_sha256": full_hash,
        "stable_sha256": stable_hash,
        "stable_range": {
            "start": PARAM_STABLE_OFFSET,
            "end": PARAM_STABLE_END,
            "size": PARAM_STABLE_SIZE,
            "sha256": stable_hash,
        },
        "stable_mask": stable_param_mask(),
        "volatile_byte0": data[0],
        "decoded_fields": fields,
    }


def classify_param_image(data: bytes) -> str:
    """Classify an exact image using stable bytes and the debug field.

    ``LOW`` accepts the post-boot byte-0 variant because that byte is the only
    excluded range.  Any change in the stable range is a hard refusal; a
    matching LOW stable image with a noncanonical four-byte debug field is a
    recoverable torn state.
    """

    evidence = stable_param_evidence(data)
    fields = evidence["decoded_fields"]
    assert isinstance(fields, Mapping)
    debug_field = data[PARAM_DEBUG_OFFSET : PARAM_DEBUG_OFFSET + 4]
    if evidence["stable_sha256"] == PARAM_STABLE_LOW_SHA256:
        if debug_field == b"DLOW":
            return "LOW"
        return "TORN"
    if evidence["stable_sha256"] == PARAM_STABLE_MID_SHA256:
        if debug_field == b"DMID":
            return "MID"
        raise ValueError("stable MID image has an unexpected debug field")
    raise ValueError("param image differs in the stable range")


def _cmdline_relevant(cmdline: dict[str, str]) -> dict[str, str | None]:
    keys = (
        "androidboot.em.model",
        "androidboot.bootloader",
        "androidboot.debug_level",
        "androidboot.force_upload",
        "sec_debug.dump_sink",
        "androidboot.upload_offset",
    )
    return {key: cmdline.get(key) for key in keys}


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


def _expected_target() -> dict[str, str]:
    return {
        "model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
    }


def _publish_incident_manifest(
    path: Path,
    *,
    experiment_id: str,
    started: str,
    status: str,
    error: str,
    journal_path: Path,
    target_verified: bool = False,
    target: Mapping[str, object] | None = None,
    effect_dispatched: bool = False,
) -> None:
    """Publish a deterministic redacted failure receipt.

    Raw cmdline, serial identity, transport payload, and transcript bytes stay
    private.  Before exact runtime gates pass, ``target`` is intentionally
    null; the fixed constants live under ``expected_target`` rather than being
    presented as an observed target claim.
    """

    manifest = {
        "schema": "sdm855-a90-param-capture-public-v1",
        "experiment_id": experiment_id,
        "started_utc": started,
        "completed_utc": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "status": status,
        "classification": status,
        "expected_target": _expected_target(),
        "target": dict(target) if target_verified and target is not None else None,
        "target_verified": bool(target_verified),
        "effect_dispatched": bool(effect_dispatched),
        "effect_replayed": False,
        "journal": journal_path.name,
        "error": f"{type(error).__name__}: {error}" if isinstance(error, BaseException) else str(error),
        "partition_writes": False,
        "redaction": {
            "raw_cmdline": "omitted",
            "serial_identity": "omitted",
            "raw_transcript": "omitted",
        },
    }
    write_new(path, json_bytes(manifest), 0o644)


def _fixed_output_root(args: argparse.Namespace) -> Path:
    """Return the fixed repository root, rejecting injected alternatives."""

    fixed_root = Path(REPO_ROOT).resolve()
    if hasattr(args, "output_root"):
        try:
            supplied_root = Path(getattr(args, "output_root")).resolve()
        except (TypeError, ValueError, OSError) as exc:
            raise ValueError("param capture output root is fixed to REPO_ROOT") from exc
        if supplied_root != fixed_root:
            raise ValueError("param capture output root is fixed to REPO_ROOT")
    return fixed_root


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("invalid experiment ID")
    if getattr(args, "execute", False) is not True:
        raise ValueError("persistent param capture requires explicit --execute")
    if args.host != "127.0.0.1" or args.port != 54321:
        raise ValueError("collector only accepts the pinned 127.0.0.1:54321 bridge")
    command_timeout = _validate_timeout(
        args.command_timeout, "command-timeout", MAX_COMMAND_TIMEOUT
    )
    capture_timeout = _validate_timeout(
        args.capture_timeout, "capture-timeout", MAX_CAPTURE_TIMEOUT
    )

    root = _fixed_output_root(args)
    private_dir = root / "evidence/private" / args.experiment_id
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    arbitration_journal_path = private_dir / "capture-journal.json"
    if (
        private_dir.exists()
        or manifest_path.exists()
        or arbitration_journal_path.exists()
        or arbitration_journal_path.is_symlink()
    ):
        raise FileExistsError("experiment output already exists")
    private_dir.mkdir(parents=True, mode=0o700)
    os.chmod(private_dir, 0o700)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    stophud_frames: list[dict[str, object]] = []
    arbitration_journal: dict[str, object] = {
        "schema": "sdm855-a90-param-capture-arbitration-journal-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "status": "STOPHUD_INTENT_DURABLE",
        "effect_dispatched": False,
        "effect_replayed": False,
        "cleanup_deferred": False,
        "reconcile_required": False,
        "cleanup_error": None,
        "stophud": None,
        "stophud_frames": stophud_frames,
        "expected_target": _expected_target(),
        "target": None,
        "target_verified": False,
    }
    _atomic_replace_json(arbitration_journal_path, arbitration_journal)

    def persist_stophud(attempts: list[dict[str, object]]) -> None:
        arbitration_journal["stophud_attempts"] = attempts
        arbitration_journal["stophud_frames"] = stophud_frames
        _atomic_replace_json(arbitration_journal_path, arbitration_journal)

    bridge_binding: Mapping[str, object] | None = None
    mutation_binding_failed = False

    def fresh_binding(label: str) -> Mapping[str, object]:
        """Revalidate exact bridge identity immediately before a mutation."""

        nonlocal mutation_binding_failed
        del label  # labels are retained by callers as an audit seam
        if bridge_binding is None:
            mutation_binding_failed = True
            raise RuntimeError("mutation group lacks an initial bridge binding")
        try:
            current = revalidate_bridge_binding(bridge_binding)
        except BaseException as exc:
            mutation_binding_failed = True
            error = f"{type(exc).__name__}: {exc}"
            arbitration_journal.update(
                {
                    "status": "CLEANUP_DEFERRED_RECONCILE_REQUIRED",
                    "cleanup_deferred": True,
                    "reconcile_required": True,
                    "cleanup_error": error,
                }
            )
            _atomic_replace_json(arbitration_journal_path, arbitration_journal)
            raise
        if not isinstance(current, Mapping) or not _bridge_bindings_match(
            bridge_binding, current
        ):
            mutation_binding_failed = True
            error = "bridge binding drifted before mutation group"
            arbitration_journal.update(
                {
                    "status": "CLEANUP_DEFERRED_RECONCILE_REQUIRED",
                    "cleanup_deferred": True,
                    "reconcile_required": True,
                    "cleanup_error": error,
                }
            )
            _atomic_replace_json(arbitration_journal_path, arbitration_journal)
            raise RuntimeError(error)
        return current

    try:
        # Bind the exact operator-owned bridge before the first stateful
        # arbitration command.  A host-side binding failure must cause zero
        # exchange/device commands and is retained in the durable journal.
        bridge_binding = validate_bridge_binding()
        if not isinstance(bridge_binding, Mapping):
            raise ValueError("initial bridge binding is not an object")
        arbitration_journal["bridge_binding"] = dict(bridge_binding)
        _atomic_replace_json(arbitration_journal_path, arbitration_journal)
        # Revalidate the exact bridge directly adjacent to stophud.  A
        # successful check performs no host fsync or other command before the
        # first stateful arbitration exchange.
        fresh_binding("pre_stophud")

        def stophud_exchange(host, port, command, timeout, **kwargs):
            # Revalidate immediately before every retry attempt.  A busy
            # refusal may be retried, but no second attempt may cross a
            # changed bridge identity.
            fresh_binding("pre_stophud_attempt")
            return exchange(host, port, command, timeout, **kwargs)

        stophud = run_stophud(
            args.host,
            args.port,
            command_timeout,
            stophud_exchange,
            frame_records=stophud_frames,
            persist=persist_stophud,
        )
        arbitration_journal["stophud"] = stophud
        arbitration_journal["status"] = "PREFLIGHT"
        _atomic_replace_json(arbitration_journal_path, arbitration_journal)
        version_frame = exchange(
            args.host, args.port, Command("version", ("version",)), command_timeout
        )
        cmdline_frame = exchange(
            args.host,
            args.port,
            Command("proc_cmdline", ("cat", "/proc/cmdline")),
            command_timeout,
        )
        cmdline = parse_cmdline(cmdline_frame.payload)
        validate_runtime(version_frame.payload, cmdline)
        validate_param_capture_cmdline(cmdline)
        dload_frame = exchange(
            args.host,
            args.port,
            Command(
                "download_mode",
                ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
            ),
            command_timeout,
        )
        dload_value = dload_frame.payload.decode("ascii", errors="strict").strip()
        if dload_value != "1":
            raise ValueError(f"download_mode precondition is {dload_value!r}, not '1'")
    except BaseException as exc:
        arbitration_journal["status"] = "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
        arbitration_journal["error"] = f"{type(exc).__name__}: {exc}"
        _atomic_replace_json(arbitration_journal_path, arbitration_journal)
        _publish_incident_manifest(
            manifest_path,
            experiment_id=args.experiment_id,
            started=started,
            status=str(arbitration_journal["status"]),
            error=str(exc),
            journal_path=arbitration_journal_path,
            target_verified=bool(arbitration_journal.get("target_verified")),
            target=arbitration_journal.get("target")
            if isinstance(arbitration_journal.get("target"), Mapping)
            else None,
        )
        raise

    try:
        partition, start_sector = discover_param(args.host, args.port, command_timeout)
        arbitration_journal["target"] = _expected_target()
        arbitration_journal["target_verified"] = True
        _atomic_replace_json(arbitration_journal_path, arbitration_journal)
    except BaseException as exc:
        arbitration_journal["status"] = "PRE_EFFECT_PREFLIGHT_INCOMPLETE"
        arbitration_journal["error"] = f"{type(exc).__name__}: {exc}"
        _atomic_replace_json(arbitration_journal_path, arbitration_journal)
        _publish_incident_manifest(
            manifest_path,
            experiment_id=args.experiment_id,
            started=started,
            status=str(arbitration_journal["status"]),
            error=str(exc),
            journal_path=arbitration_journal_path,
            target_verified=bool(arbitration_journal.get("target_verified")),
            target=arbitration_journal.get("target")
            if isinstance(arbitration_journal.get("target"), Mapping)
            else None,
        )
        raise
    partial_path = private_dir / "param--sda10.bin.partial"
    final_path = private_dir / "param--sda10.bin"
    capture_error: BaseException | None = None
    cleanup_error: str | None = None
    try:
        create_and_validate_node(
            args.host,
            args.port,
            partition,
            command_timeout,
            before_mutation=fresh_binding,
        )
        before = device_sha256(
            args.host, args.port, partition, command_timeout, "before"
        )
        end_fields, payload = binary_exchange(
            args.host,
            args.port,
            partition.node_path,
            PARAM_PARTITION_BYTES,
            capture_timeout,
        )
        host_hash = sha256(payload)
        stable_hash = stable_param_sha256(payload)
        volatile_byte0 = payload[0]
        write_new(partial_path, payload, 0o600)
        after = device_sha256(
            args.host, args.port, partition, command_timeout, "after"
        )
        if before != host_hash or after != host_hash:
            raise ValueError(
                "independent param hash mismatch: "
                f"before={before} host={host_hash} after={after}"
            )
        os.rename(partial_path, final_path)
        fsync_directory(private_dir)
    except BaseException as exc:
        capture_error = exc
    finally:
        # A temporary block-device node is itself a device-side mutation.  A
        # fresh, matching host-only bridge binding is required immediately
        # before its removal; if continuity cannot be proved, do not send a
        # cleanup command through an untrusted bridge.
        try:
            if mutation_binding_failed:
                raise RuntimeError("bridge binding had already drifted before cleanup")
            cleanup_binding = revalidate_bridge_binding(bridge_binding)
            if not isinstance(cleanup_binding, Mapping) or not _bridge_bindings_match(
                bridge_binding, cleanup_binding
            ):
                raise RuntimeError("bridge binding drifted before param-node cleanup")
        except BaseException as exc:
            cleanup_error = f"{type(exc).__name__}: {exc}"
            arbitration_journal.update(
                {
                    "status": "CLEANUP_DEFERRED_RECONCILE_REQUIRED",
                    "cleanup_deferred": True,
                    "reconcile_required": True,
                    "cleanup_error": cleanup_error,
                    "error": (
                        f"capture={type(capture_error).__name__}: {capture_error}; "
                        f"cleanup={cleanup_error}"
                        if capture_error is not None
                        else cleanup_error
                    ),
                }
            )
            _atomic_replace_json(arbitration_journal_path, arbitration_journal)
        else:
            try:
                remove_node(args.host, args.port, partition, command_timeout)
            except BaseException as exc:
                cleanup_error = f"{type(exc).__name__}: {exc}"
                arbitration_journal.update(
                    {
                        "status": "CLEANUP_DEFERRED_RECONCILE_REQUIRED",
                        "cleanup_deferred": True,
                        "reconcile_required": True,
                        "cleanup_error": cleanup_error,
                        "error": (
                            f"capture={type(capture_error).__name__}: {capture_error}; "
                            f"cleanup={cleanup_error}"
                            if capture_error is not None
                            else cleanup_error
                        ),
                    }
                )
                _atomic_replace_json(arbitration_journal_path, arbitration_journal)

    if capture_error is not None:
        if cleanup_error is None:
            arbitration_journal.update(
                {
                    "status": "PRE_EFFECT_CAPTURE_INCOMPLETE",
                    "error": f"{type(capture_error).__name__}: {capture_error}",
                }
            )
            _atomic_replace_json(arbitration_journal_path, arbitration_journal)
        _publish_incident_manifest(
            manifest_path,
            experiment_id=args.experiment_id,
            started=started,
            status=str(arbitration_journal["status"]),
            error=str(capture_error),
            journal_path=arbitration_journal_path,
            target_verified=bool(arbitration_journal.get("target_verified")),
            target=arbitration_journal.get("target")
            if isinstance(arbitration_journal.get("target"), Mapping)
            else None,
        )
        raise capture_error
    if cleanup_error is not None:
        _publish_incident_manifest(
            manifest_path,
            experiment_id=args.experiment_id,
            started=started,
            status=str(arbitration_journal["status"]),
            error=cleanup_error,
            journal_path=arbitration_journal_path,
            target_verified=bool(arbitration_journal.get("target_verified")),
            target=arbitration_journal.get("target")
            if isinstance(arbitration_journal.get("target"), Mapping)
            else None,
        )
        raise RuntimeError(f"param-node cleanup was not proved: {cleanup_error}")

    fields = decode_fields(payload)
    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    private_metadata = {
        "schema": "sdm855-a90-param-capture-private-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "stophud": stophud,
        "stophud_frames": stophud_frames,
        "bridge_binding": dict(bridge_binding),
        "arbitration_journal": arbitration_journal_path.name,
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime_payload": version_frame.payload.decode("ascii", errors="strict"),
        "cmdline": cmdline,
        "download_mode": dload_value,
        "partition": {
            **partition.__dict__,
            "start_sector": start_sector,
            "node_path": partition.node_path,
        },
        "capture": {
            "private_filename": final_path.name,
            "size": len(payload),
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
                "stable_ranges": [list(item) for item in PARAM_STABLE_RANGES],
                "stable_size": PARAM_STABLE_SIZE,
            },
            "volatile_byte0": volatile_byte0,
            "observed_boot_cycle_volatile_byte0": volatile_byte0,
            "device_sha256_before": before,
            "device_sha256_after": after,
            "a90p1_end": end_fields,
        },
        "stable_sha256": stable_hash,
        "stable_range": {
            "start": PARAM_STABLE_OFFSET,
            "end": PARAM_STABLE_END,
            "size": PARAM_STABLE_SIZE,
            "sha256": stable_hash,
        },
        "stable_mask": {
            "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
            "stable_ranges": [list(item) for item in PARAM_STABLE_RANGES],
            "stable_size": PARAM_STABLE_SIZE,
        },
        "volatile_byte0": volatile_byte0,
        "observed_boot_cycle_volatile_byte0": volatile_byte0,
        "decoded_gate_fields": fields,
        "partition_writes": False,
        "filesystem_only_mutations": [
            "temporary fixed block-device node creation under /dev",
            "temporary fixed block-device node removal under /dev",
        ],
    }
    private_metadata_path = private_dir / "capture-metadata.json"
    write_new(private_metadata_path, json_bytes(private_metadata), 0o600)

    arbitration_journal.update(
        {
            "status": "COMPLETE",
            "completed_utc": completed,
            "retained_size": len(payload),
            "retained_sha256": host_hash,
            "retained_stable_sha256": stable_hash,
            "retained_volatile_byte0": volatile_byte0,
            "private_metadata": private_metadata_path.name,
        }
    )
    _atomic_replace_json(arbitration_journal_path, arbitration_journal)

    manifest = {
        "schema": "sdm855-a90-param-capture-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "stophud_accepted": bool(stophud.get("accepted")),
        "stophud_busy_retries": stophud.get("busy_retries", 0),
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
        "bootloader": TARGET_BOOTLOADER,
        "partition": {
            "partname": partition.partname,
            "devname": partition.devname,
            "major": partition.major,
            "minor": partition.minor,
            "sectors": partition.sectors,
            "byte_size": partition.byte_size,
            "start_sector": start_sector,
            "read_only": partition.read_only,
            "logical_block_size": partition.logical_block_size,
        },
        "capture": {
            "size": len(payload),
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
                "stable_ranges": [list(item) for item in PARAM_STABLE_RANGES],
                "stable_size": PARAM_STABLE_SIZE,
            },
            "volatile_byte0": volatile_byte0,
            "observed_boot_cycle_volatile_byte0": volatile_byte0,
            "device_sha256_before": before,
            "device_sha256_after": after,
            "triple_hash_match": before == host_hash == after,
        },
        "stable_sha256": stable_hash,
        "stable_range": {
            "start": PARAM_STABLE_OFFSET,
            "end": PARAM_STABLE_END,
            "size": PARAM_STABLE_SIZE,
            "sha256": stable_hash,
        },
        "stable_mask": {
            "excluded_ranges": [list(item) for item in PARAM_VOLATILE_RANGES],
            "stable_ranges": [list(item) for item in PARAM_STABLE_RANGES],
            "stable_size": PARAM_STABLE_SIZE,
        },
        "volatile_byte0": volatile_byte0,
        "observed_boot_cycle_volatile_byte0": volatile_byte0,
        "decoded_gate_fields": fields,
        "cmdline_relevant": _cmdline_relevant(cmdline),
        "download_mode": dload_value,
        "classification": (
            "PARAM_CAPTURED_DEBUG_ONLY_PRECONDITIONS_MET"
            if stable_hash == PARAM_STABLE_LOW_SHA256
            and _cmdline_relevant(cmdline)
            == {
                "androidboot.em.model": TARGET_MODEL,
                "androidboot.bootloader": TARGET_BOOTLOADER,
                "androidboot.debug_level": "0x4f4c",
                "androidboot.force_upload": "0x0",
                "sec_debug.dump_sink": "0x0",
                "androidboot.upload_offset": PARAM_CMDLINE_UPLOAD_OFFSET,
            }
            and fields["debuglevel"]["label"] == "LOW"
            and fields["force_upload_flag"]["value"] == "0x00000000"
            and fields["FMM_lock"]["label"] == "NOT_LOCK_MAGIC"
            and fields["dump_sink"]["label"] == "USB_DEFAULT"
            and dload_value == "1"
            else "PARAM_CAPTURED_REEVALUATION_REQUIRED"
        ),
        "partition_writes": False,
        "raw_artifact_git_ignored": True,
        "claims": {
            "PROVED": [
                "The exact live sda10/PARTNAME=param partition was captured byte-for-byte and matched independent device-before, host, and device-after SHA-256 values.",
                "Stable eligibility uses the exact [1,0xA00000) SHA-256 and decoded debug fields; byte [0,1) is retained as an observed boot-cycle volatile value.",
                "The four XBL gate fields were decoded at exact source-backed offsets in the retained rollback artifact.",
            ],
            "UNKNOWN": [
                "No persistent state was changed, so post-change XBL behavior remains untested by this capture.",
            ],
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return private_metadata_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--command-timeout", type=float, default=45.0)
    parser.add_argument("--capture-timeout", type=float, default=240.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    private_metadata, manifest = collect(args)
    print(f"private metadata: {private_metadata}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
