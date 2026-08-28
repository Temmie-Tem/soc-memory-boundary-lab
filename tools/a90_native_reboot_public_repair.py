#!/usr/bin/env python3
"""Host-only repair of the fixed Verification-024 native-reboot projection.

The live reboot has already happened and must never be replayed by this
module.  It only reads the pinned legacy public manifest, its private journal,
and its private physical-effect claim.  A one-shot repair archives the exact
legacy bytes with ``O_EXCL`` before atomically replacing the public file with a
deterministic, UUID-redacted v2 projection.  The repository root and every
input path are fixed constants; tests patch ``REPO_ROOT`` rather than passing
an alternate evidence universe to the repair function.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Mapping

try:
    from tools.a90_v024_physical_claim import (
        NATIVE_TRANSITION_CLAIM_SCHEMA,
        NATIVE_TRANSITION_RESOURCE,
        native_transition_claim_identity,
        native_transition_claim_path,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_v024_physical_claim import (  # type: ignore
        NATIVE_TRANSITION_CLAIM_SCHEMA,
        NATIVE_TRANSITION_RESOURCE,
        native_transition_claim_identity,
        native_transition_claim_path,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT_ID = "verification-024-control-reboot-mid"
PUBLIC_MANIFEST_NAME = f"{EXPERIMENT_ID}.manifest.json"
JOURNAL_NAME = f"{EXPERIMENT_ID}.journal.json"
LEGACY_ARCHIVE_NAME = f"{EXPERIMENT_ID}.v1.manifest.json"
PUBLIC_MANIFEST_SCHEMA_V1 = "sdm855-a90-native-reboot-public-v1"
PUBLIC_MANIFEST_SCHEMA_V2 = "sdm855-a90-native-reboot-public-v2"
JOURNAL_SCHEMA = "sdm855-a90-native-reboot-journal-v1"
LEGACY_PUBLIC_SIZE = 1884
LEGACY_PUBLIC_SHA256 = (
    "3a91e6eac449663c75d3ba4b1e7d6d681db30cee86c5b5f2e5986241ef0d80ca"
)
JOURNAL_SIZE = 22905
JOURNAL_SHA256 = (
    "8760aa1f64372b8c572396d37b9a6a72952330d1e339d5c2bc55a19547200cf8"
)
CLAIM_NAME = (
    "verification-024-native-boot-transition-"
    "fab98190df754dfb1d2ae5a4a3372c64fca7b1da9b22ff27f7905b259b47a366.claim.json"
)
CLAIM_SIZE = 663
CLAIM_SHA256 = (
    "03d1f63e5c16cc9f887e6993004bad1b75d3bae0507a02db8922d287008b1802"
)
TARGET_MODEL = "SM-A908N"
TARGET_SOC = "SM8150"
TARGET_BOOTLOADER = "A908NKSU5EWA3"
TARGET_RUNTIME = "v2321-usb-clean-identity-rodata"
TARGET_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
BOOT_ID_SUBSTRING_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES = 8 * 1024 * 1024


class RepairError(RuntimeError):
    """The fixed legacy/public repair state is incomplete or unsafe."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _reject_symlink_components(path: Path, label: str) -> None:
    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise RepairError(f"{label} component must not be a symlink: {cursor}")
        if cursor == anchor:
            return
        cursor = cursor.parent


def _fixed_root() -> Path:
    root = Path(REPO_ROOT)
    _reject_symlink_components(root, "repair root")
    resolved = root.resolve(strict=False)
    if resolved != root.resolve(strict=False):  # pragma: no cover - defensive
        raise RepairError("repair root changed while resolving")
    return resolved


def _fixed_paths(root: Path) -> tuple[Path, Path, Path, Path]:
    evidence = root / "evidence"
    public = evidence / "manifests" / PUBLIC_MANIFEST_NAME
    journal = evidence / "private" / JOURNAL_NAME
    claim = evidence / "private" / CLAIM_NAME
    archive = evidence / "private" / LEGACY_ARCHIVE_NAME
    for path, label in (
        (public, "public manifest"),
        (journal, "private journal"),
        (claim, "private claim"),
        (archive, "legacy archive"),
    ):
        _reject_symlink_components(path, label)
    return public, journal, claim, archive


def _read_stable(
    path: Path,
    *,
    label: str,
    expected_size: int | None,
    expected_sha256: str | None,
    expected_mode: int,
) -> bytes:
    """Read a pinned regular file while retaining inode and owner identity."""

    _reject_symlink_components(path, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RepairError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RepairError(f"{label} is not a regular file")
        if stat.S_IMODE(before.st_mode) != expected_mode:
            raise RepairError(f"{label} mode is not pinned")
        if before.st_uid != os.getuid() or before.st_gid != os.getgid():
            raise RepairError(f"{label} owner is not the evidence owner")
        if (
            (expected_size is not None and before.st_size != expected_size)
            or before.st_size > MAX_FILE_BYTES
        ):
            raise RepairError(f"{label} size is not pinned")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise RepairError(f"{label} exceeds the fixed size bound")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or (
            expected_size is not None and total != expected_size
        ):
            raise RepairError(f"{label} changed while being read")
        data = b"".join(chunks)
        if expected_size is not None and len(data) != expected_size:
            raise RepairError(f"{label} byte size is not the pinned receipt")
        if expected_sha256 is not None and sha256(data) != expected_sha256:
            raise RepairError(f"{label} hash or size is not the pinned receipt")
        return data
    finally:
        os.close(descriptor)


def _read_archive(path: Path, legacy: bytes) -> bytes:
    if not path.exists() or path.is_symlink():
        raise RepairError("legacy v1 archive is missing or is a symlink")
    return _read_stable(
        path,
        label="legacy v1 archive",
        expected_size=len(legacy),
        expected_sha256=sha256(legacy),
        expected_mode=0o600,
    )


def _strict_json(data: bytes, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise RepairError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise RepairError(f"{label} contains non-finite JSON number {value}")

    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant
        )
    except RepairError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepairError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise RepairError(f"{label} root is not an object")
    return value


def _require(obj: Mapping[str, object], key: str, expected: object, label: str) -> None:
    if type(obj.get(key)) is not type(expected) or obj.get(key) != expected:
        raise RepairError(f"{label} field {key!r} is not exact")


def _legacy_public_projection(journal: Mapping[str, object]) -> dict[str, object]:
    """Reconstruct the exact v1 projection emitted by the old collector."""

    _require(journal, "schema", JOURNAL_SCHEMA, "pinned journal")
    _require(journal, "experiment_id", EXPERIMENT_ID, "pinned journal")
    _require(journal, "status", "NEW_BOOT_PROVED", "pinned journal")
    _require(journal, "effect", "cmdv1 reboot", "pinned journal")
    _require(journal, "effect_dispatched", True, "pinned journal")
    _require(journal, "effect_replayed", False, "pinned journal")
    before = journal.get("before")
    after = journal.get("after")
    physical = journal.get("physical_effect_claim")
    pre_stophud = journal.get("pre_stophud")
    dispatch = journal.get("dispatch_receipt")
    if not all(
        isinstance(item, Mapping)
        for item in (before, after, physical, pre_stophud, dispatch)
    ):
        raise RepairError("pinned journal lacks the complete legacy projection")
    boot_id = before.get("boot_id")
    after_boot_id = after.get("boot_id")
    if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
        raise RepairError("pinned journal pre-effect UUID is malformed")
    if not isinstance(after_boot_id, str) or BOOT_ID_RE.fullmatch(after_boot_id) is None:
        raise RepairError("pinned journal post-effect UUID is malformed")
    if physical.get("boot_id") != boot_id:
        raise RepairError("pinned journal claim UUID differs from before")
    if physical.get("claimed") is not True or physical.get("attempted") is not True:
        raise RepairError("pinned journal physical claim is incomplete")
    if after_boot_id == boot_id:
        raise RepairError("pinned journal did not prove a changed boot UUID")
    required_after = ("cmdline", "download_mode", "selftest", "stophud")
    if any(key not in after for key in required_after):
        raise RepairError("pinned journal post-boot facts are incomplete")
    after_cmdline = after.get("cmdline")
    if not isinstance(after_cmdline, Mapping):
        raise RepairError("pinned journal post-boot cmdline is missing")
    for key, expected in {
        "androidboot.debug_level": "0x494d",
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
    }.items():
        _require(after_cmdline, key, expected, "pinned journal post-boot cmdline")
    _require(after, "download_mode", "1", "pinned journal post-boot")
    selftest = after.get("selftest")
    if not isinstance(selftest, Mapping):
        raise RepairError("pinned journal post-boot selftest is missing")
    for key, expected in {
        "passed": 11,
        "warn": 1,
        "fail": 0,
        "duration": 43,
        "entries": 12,
    }.items():
        _require(selftest, key, expected, "pinned journal post-boot selftest")
    for scope, stophud in (
        ("pre_stophud", pre_stophud),
        ("post_stophud", after.get("stophud")),
    ):
        if not isinstance(stophud, Mapping):
            raise RepairError(f"pinned journal {scope} is missing")
        _require(stophud, "accepted", True, f"pinned journal {scope}")
        retries = stophud.get("busy_retries")
        if type(retries) is not int or retries < 0 or retries > 3:
            raise RepairError(f"pinned journal {scope} retry count is not bounded")
    dispatch_required = {
        "a90p1_begin_observed": True,
        "reboot_marker_observed": True,
        "socket_disconnect_observed": True,
    }
    for key, expected in dispatch_required.items():
        _require(dispatch, key, expected, "pinned journal dispatch receipt")
    begin = dispatch.get("begin")
    if not isinstance(begin, Mapping) or dict(begin) != {
        "argc": "1",
        "cmd": "reboot",
        "flags": "0x14",
        "seq": begin.get("seq") if isinstance(begin, Mapping) else None,
    }:
        raise RepairError("pinned journal dispatch BEGIN is not exact")
    if not isinstance(begin.get("seq"), str) or not begin["seq"].isdigit() or (
        len(begin["seq"]) > 1 and begin["seq"].startswith("0")
    ):
        raise RepairError("pinned journal dispatch sequence is not canonical")
    dispatch_public = {
        key: value for key, value in dispatch.items() if key != "transcript_base64"
    }
    return {
        "schema": PUBLIC_MANIFEST_SCHEMA_V1,
        "experiment_id": EXPERIMENT_ID,
        "started_utc": journal.get("started_utc"),
        "completed_utc": journal.get("completed_utc"),
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
        "classification": "NEW_BOOT_PROVED",
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "cmd_no_done": True,
        "dispatch_receipt": dispatch_public,
        "physical_effect_claim": {
            "claimed": True,
            "attempted": True,
            "key_sha256": physical.get("key_sha256"),
            "claim_sha256": physical.get("claim_sha256"),
            "claim_size": physical.get("claim_size"),
            "boot_id": boot_id,
        },
        "pre_stophud_accepted": pre_stophud.get("accepted"),
        "pre_stophud_busy_retries": pre_stophud.get("busy_retries"),
        "boot_id_changed": boot_id != after_boot_id,
        "post_boot": {
            "debug_level": after["cmdline"].get("androidboot.debug_level"),
            "force_upload": after["cmdline"].get("androidboot.force_upload"),
            "dump_sink": after["cmdline"].get("sec_debug.dump_sink"),
            "download_mode": after.get("download_mode"),
            "selftest": after.get("selftest"),
            "stophud_accepted": after["stophud"].get("accepted"),
            "stophud_busy_retries": after["stophud"].get("busy_retries"),
        },
        "claims": {
            "PROVED": [
                "The reboot command was dispatched exactly once and accepted by the exact A90P1 CMD_NO_DONE path.",
                "A different boot ID returned with the exact native runtime and requested source-backed debug-level cmdline value.",
            ]
        },
    }


def _validate_private_claim(
    root: Path, journal: Mapping[str, object], claim_path: Path, claim_data: bytes
) -> tuple[str, str]:
    physical = journal.get("physical_effect_claim")
    before = journal.get("before")
    if not isinstance(physical, Mapping) or not isinstance(before, Mapping):
        raise RepairError("private claim binding is incomplete")
    boot_id = before.get("boot_id")
    if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
        raise RepairError("private claim source UUID is malformed")
    if physical.get("boot_id") != boot_id:
        raise RepairError("private claim UUID differs from journal before")
    try:
        identity, key = native_transition_claim_identity(boot_id)
        expected_path = native_transition_claim_path(root, key).resolve(strict=False)
    except Exception as exc:
        raise RepairError("private claim identity is not canonical") from exc
    if claim_path.resolve(strict=False) != expected_path or claim_path.name != CLAIM_NAME:
        raise RepairError("private claim path is not the fixed canonical path")
    claim = _strict_json(claim_data, "private claim")
    if (
        claim.get("schema") != NATIVE_TRANSITION_CLAIM_SCHEMA
        or claim.get("claim_key_sha256") != key
        or claim.get("claim_identity") != identity
        or claim.get("claimed_by_experiment_id") != EXPERIMENT_ID
        or claim.get("effect_replayed") is not False
        or claim.get("claim_status") != "COMPLETE"
    ):
        raise RepairError("private claim schema/key/owner/effect is not exact")
    if not isinstance(claim.get("provenance"), Mapping):
        raise RepairError("private claim provenance is missing")
    if physical.get("key_sha256") != key:
        raise RepairError("journal claim key is not bound")
    if physical.get("claim_sha256") != sha256(claim_data):
        raise RepairError("journal claim hash is not bound")
    if physical.get("claim_size") != len(claim_data):
        raise RepairError("journal claim size is not bound")
    return boot_id, key


def _public_v2_projection(
    journal: Mapping[str, object], journal_data: bytes, boot_id: str
) -> dict[str, object]:
    before = journal.get("before")
    after = journal.get("after")
    physical = journal.get("physical_effect_claim")
    pre_stophud = journal.get("pre_stophud")
    dispatch = journal.get("dispatch_receipt")
    if not all(
        isinstance(item, Mapping)
        for item in (before, after, physical, pre_stophud, dispatch)
    ):
        raise RepairError("private journal lacks complete v2 facts")
    if BOOT_ID_RE.fullmatch(boot_id) is None:
        raise RepairError("v2 source UUID is malformed")
    _require(journal, "experiment_id", EXPERIMENT_ID, "v2 journal")
    _require(journal, "schema", JOURNAL_SCHEMA, "v2 journal")
    _require(journal, "status", "NEW_BOOT_PROVED", "v2 journal")
    _require(journal, "effect", "cmdv1 reboot", "v2 journal")
    _require(journal, "effect_dispatched", True, "v2 journal")
    _require(journal, "effect_replayed", False, "v2 journal")
    if before.get("boot_id") != boot_id or after.get("boot_id") == boot_id:
        raise RepairError("v2 journal boot IDs are not bound")
    after_cmdline = after.get("cmdline")
    after_stophud = after.get("stophud")
    if not isinstance(after_cmdline, Mapping) or not isinstance(after_stophud, Mapping):
        raise RepairError("v2 post-boot facts are incomplete")
    return {
        "schema": PUBLIC_MANIFEST_SCHEMA_V2,
        "experiment_id": journal.get("experiment_id"),
        "started_utc": journal.get("started_utc"),
        "completed_utc": journal.get("completed_utc"),
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
        "classification": journal.get("status"),
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "cmd_no_done": True,
        "dispatch_receipt": {
            key: value for key, value in dispatch.items() if key != "transcript_base64"
        },
        "physical_effect_claim": {
            "claimed": True,
            "attempted": True,
            "key_sha256": physical.get("key_sha256"),
            "claim_sha256": physical.get("claim_sha256"),
            "claim_size": physical.get("claim_size"),
            "boot_id_sha256": sha256(boot_id.encode("ascii")),
        },
        "private_journal": {
            "filename": JOURNAL_NAME,
            "sha256": sha256(journal_data),
            "size": len(journal_data),
            "git_ignored": True,
        },
        "pre_stophud_accepted": pre_stophud.get("accepted"),
        "pre_stophud_busy_retries": pre_stophud.get("busy_retries"),
        "boot_id_changed": before.get("boot_id") != after.get("boot_id"),
        "post_boot": {
            "debug_level": after_cmdline.get("androidboot.debug_level"),
            "force_upload": after_cmdline.get("androidboot.force_upload"),
            "dump_sink": after_cmdline.get("sec_debug.dump_sink"),
            "download_mode": after.get("download_mode"),
            "selftest": after.get("selftest"),
            "stophud_accepted": after_stophud.get("accepted"),
            "stophud_busy_retries": after_stophud.get("busy_retries"),
        },
        "claims": {
            "PROVED": [
                "The reboot command was dispatched exactly once and accepted by the exact A90P1 CMD_NO_DONE path.",
                "A different boot ID returned with the exact native runtime and requested source-backed debug-level cmdline value.",
            ]
        },
    }


def _reject_public_private_data(value: object, label: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in {
                "boot_id",
                "claim_path",
                "journal_path",
                "serial",
                "serial_device",
                "serial_identity",
            }:
                raise RepairError(f"{label} exposes private field {key!r}")
            _reject_public_private_data(item, label)
    elif isinstance(value, list):
        for item in value:
            _reject_public_private_data(item, label)
    elif isinstance(value, str):
        if BOOT_ID_SUBSTRING_RE.search(value) is not None:
            raise RepairError(f"{label} exposes a raw boot UUID")
        if value.startswith(("/", "~", "file://")):
            raise RepairError(f"{label} exposes a private absolute path")


def _write_exclusive_archive(path: Path, data: bytes) -> None:
    _reject_symlink_components(path.parent, "legacy archive")
    if path.exists() or path.is_symlink():
        raise RepairError("legacy archive already exists; repair state is partial")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RepairError("legacy archive could not be claimed exclusively") from exc
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RepairError("legacy archive short write")
            view = view[written:]
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != len(data):
            raise RepairError("legacy archive size changed before publication")
    except BaseException:
        # Leave a failed archive inode as immutable reconciliation evidence;
        # never silently unlink a partial archive and retry the repair.
        raise
    finally:
        os.close(descriptor)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.open(path.parent, directory_flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _replace_public(path: Path, data: bytes) -> None:
    """Publish v2 only after the archive is durable."""

    _reject_symlink_components(path.parent, "public manifest")
    temporary = path.with_name(path.name + ".v2.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RepairError("v2 temporary publication residue exists")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o644)
    except OSError as exc:
        raise RepairError("v2 temporary publication could not be created") from exc
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RepairError("v2 temporary short write")
            view = view[written:]
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        if (
            not stat.S_ISREG(staged.st_mode)
            or stat.S_IMODE(staged.st_mode) != 0o644
            or staged.st_size != len(data)
        ):
            raise RepairError("v2 temporary inode is not exact")
        try:
            named = os.stat(temporary, follow_symlinks=False)
        except OSError as exc:
            raise RepairError("v2 temporary disappeared before publication") from exc
        if (
            named.st_dev,
            named.st_ino,
            named.st_mode,
            named.st_size,
        ) != (
            staged.st_dev,
            staged.st_ino,
            staged.st_mode,
            staged.st_size,
        ):
            raise RepairError("v2 temporary pathname was substituted")
        # The old public inode is intentionally replaced only after the
        # archive's fsync completed.  Keep the staged FD open across rename
        # and verify that the published name still denotes that exact inode.
        try:
            os.replace(temporary, path)
        except OSError as exc:
            raise RepairError("v2 public manifest atomic replacement failed") from exc
        try:
            published = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise RepairError("v2 public manifest disappeared after replacement") from exc
        if (
            published.st_dev,
            published.st_ino,
            published.st_mode,
            published.st_size,
        ) != (
            staged.st_dev,
            staged.st_ino,
            staged.st_mode,
            staged.st_size,
        ):
            raise RepairError("v2 public manifest inode was substituted")
        final_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        if hasattr(os, "O_CLOEXEC"):
            final_flags |= os.O_CLOEXEC
        try:
            final_fd = os.open(path, final_flags)
        except OSError as exc:
            raise RepairError("v2 public manifest cannot be reopened safely") from exc
        try:
            final_stat = os.fstat(final_fd)
            if (
                final_stat.st_dev,
                final_stat.st_ino,
                final_stat.st_mode,
                final_stat.st_size,
            ) != (
                staged.st_dev,
                staged.st_ino,
                staged.st_mode,
                staged.st_size,
            ):
                raise RepairError("v2 public manifest final inode differs")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(final_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            final_data = b"".join(chunks)
            if len(final_data) != len(data) or sha256(final_data) != sha256(data):
                raise RepairError("v2 public manifest final bytes differ")
        finally:
            os.close(final_fd)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(descriptor)


def _verify_final_state(
    root: Path,
    public_path: Path,
    journal_path: Path,
    claim_path: Path,
    archive_path: Path,
) -> Path:
    """Re-read every source and both outputs immediately before success.

    This is deliberately shared by a fresh repair and an idempotent
    verification.  A same-owner mutation after archive creation but before
    public replacement therefore cannot leave a stale journal/claim binding
    looking successful.
    """

    journal_data = _read_stable(
        journal_path,
        label="final private journal",
        expected_size=JOURNAL_SIZE,
        expected_sha256=JOURNAL_SHA256,
        expected_mode=0o600,
    )
    journal = _strict_json(journal_data, "final private journal")
    claim_data = _read_stable(
        claim_path,
        label="final private claim",
        expected_size=CLAIM_SIZE,
        expected_sha256=CLAIM_SHA256,
        expected_mode=0o600,
    )
    boot_id, _key = _validate_private_claim(root, journal, claim_path, claim_data)
    expected_public = _json_bytes(_public_v2_projection(journal, journal_data, boot_id))
    public_data = _read_stable(
        public_path,
        label="final v2 public manifest",
        expected_size=len(expected_public),
        expected_sha256=sha256(expected_public),
        expected_mode=0o644,
    )
    if public_data != expected_public:
        raise RepairError("final v2 public manifest differs from pinned sources")
    public = _strict_json(public_data, "final v2 public manifest")
    if public.get("schema") != PUBLIC_MANIFEST_SCHEMA_V2:
        raise RepairError("final public manifest is not v2")
    _reject_public_private_data(public, "final v2 public manifest")
    legacy_public = _json_bytes(_legacy_public_projection(journal))
    archive = _read_archive(archive_path, legacy_public)
    if archive != legacy_public:
        raise RepairError("final legacy archive differs from pinned v1 bytes")
    return public_path


def repair_legacy_public_manifest() -> Path:
    """Perform or verify the one-shot fixed-path v1 -> v2 public repair."""

    root = _fixed_root()
    public_path, journal_path, claim_path, archive_path = _fixed_paths(root)
    if not public_path.exists() or public_path.is_symlink():
        raise RepairError("fixed legacy public manifest is missing")
    # Detect v2 without trusting it, then verify every source and binding
    # below.  This branch is deliberately no-op only when the archive is also
    # present and exact.
    public_probe = _read_stable(
        public_path,
        label="public manifest",
        expected_size=None,
        expected_sha256=None,
        expected_mode=0o644,
    )
    try:
        public_value = _strict_json(public_probe, "public manifest")
    except RepairError:
        raise
    if public_value.get("schema") == PUBLIC_MANIFEST_SCHEMA_V2:
        return _verify_final_state(root, public_path, journal_path, claim_path, archive_path)

    if public_value.get("schema") != PUBLIC_MANIFEST_SCHEMA_V1:
        raise RepairError("fixed public manifest is neither pinned v1 nor repaired v2")
    if len(public_probe) != LEGACY_PUBLIC_SIZE or sha256(public_probe) != LEGACY_PUBLIC_SHA256:
        raise RepairError("legacy public manifest does not match the pinned bytes")
    # The pinned read above is the legacy public itself.  Re-open and pin the
    # private sources before creating any archive or replacement inode.
    journal_data = _read_stable(
        journal_path,
        label="private journal",
        expected_size=JOURNAL_SIZE,
        expected_sha256=JOURNAL_SHA256,
        expected_mode=0o600,
    )
    journal = _strict_json(journal_data, "private journal")
    legacy_expected = _json_bytes(_legacy_public_projection(journal))
    if public_probe != legacy_expected:
        raise RepairError("legacy public bytes do not reconstruct from pinned journal")
    claim_data = _read_stable(
        claim_path,
        label="private claim",
        expected_size=CLAIM_SIZE,
        expected_sha256=CLAIM_SHA256,
        expected_mode=0o600,
    )
    boot_id, _key = _validate_private_claim(root, journal, claim_path, claim_data)
    if archive_path.exists() or archive_path.is_symlink():
        raise RepairError("legacy public plus archive is a partial repair state")
    v2_expected = _public_v2_projection(journal, journal_data, boot_id)
    v2_data = _json_bytes(v2_expected)
    # Apply the privacy gate to the exact in-memory projection before any
    # archive or public inode mutation.  A future projection regression must
    # fail while the pinned legacy bytes are still untouched.
    _reject_public_private_data(v2_expected, "repaired v2 public manifest")
    _write_exclusive_archive(archive_path, public_probe)
    _replace_public(public_path, v2_data)
    # Validate the final state from disk, including privacy and exact source
    # hashes.  If any post-replace validation fails, the archive and v2 inode
    # remain for explicit reconciliation instead of triggering a replay.
    return _verify_final_state(root, public_path, journal_path, claim_path, archive_path)


# Short aliases make the host-only seam straightforward to call from a
# review harness without introducing an alternate path/root argument.
repair = repair_legacy_public_manifest
verify_repaired_state = repair_legacy_public_manifest


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(description=__doc__)


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    print(f"public manifest: {repair_legacy_public_manifest()}")
    return 0


if __name__ == "__main__":  # pragma: no cover - explicit host CLI
    raise SystemExit(main())
