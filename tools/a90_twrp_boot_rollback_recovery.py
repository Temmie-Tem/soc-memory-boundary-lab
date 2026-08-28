#!/usr/bin/env python3
"""Mechanically recover one ambiguous Verification 024 boot-prefix write.

This owner is intentionally separate from the normal candidate predecessor
graph.  It accepts only a stable, no-follow reference to a durable ambiguous
V024 flash journal whose write was armed exactly once and whose current state
is explicitly unknown/partial.  It then binds the pinned A90 Recovery/TWRP
endpoint, stages the one fixed V2321 rollback image, and publishes a durable
marker before at most one fixed boot-prefix ``dd``.  A transport exception
after that marker is permanently ambiguous and never causes a replay.

Importing this module performs no filesystem, subprocess, ADB, or device
contact.  The public CLI has no image, block, profile, transport, retry, or
timeout selectors; tests replace the narrow local/transport seams.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from typing import Any, Mapping, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes
    from tools.a90_twrp_system_boot import (
        AdbEndpoint,
        TARGET_DEVICE,
        TARGET_MODEL,
        TARGET_SERIAL_SHA256,
        TWRP_VERSION,
        parse_adb_devices,
        select_exact_recovery,
    )
    from tools.a90_v024_physical_claim import (
        ClaimRecord,
        PhysicalClaimAlreadyExists,
        PhysicalClaimError,
        PhysicalClaimPartial,
        boot_prefix_claim_identity,
        boot_prefix_claim_path,
        claim_boot_prefix,
        create_boot_prefix_claim,
        inspect_boot_prefix_claim,
        validate_normal_remapper_continuation,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes  # type: ignore
    from a90_twrp_system_boot import (  # type: ignore
        AdbEndpoint,
        TARGET_DEVICE,
        TARGET_MODEL,
        TARGET_SERIAL_SHA256,
        TWRP_VERSION,
        parse_adb_devices,
        select_exact_recovery,
    )
    from a90_v024_physical_claim import (  # type: ignore
        ClaimRecord,
        PhysicalClaimAlreadyExists,
        PhysicalClaimError,
        PhysicalClaimPartial,
        boot_prefix_claim_identity,
        boot_prefix_claim_path,
        claim_boot_prefix,
        create_boot_prefix_claim,
        inspect_boot_prefix_claim,
        validate_normal_remapper_continuation,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = REPO_ROOT
# The Recovery transport is part of this owner's fixed identity.  Use the
# installed regular-file binary rather than inheriting a PATH-selected adb.
ADB = "/usr/lib/android-sdk/platform-tools/adb"

BOOT_PREFIX_SIZE = 60_882_944
BOOT_BLOCK_ALIAS = "/dev/block/by-name/boot"
BOOT_BLOCK_RESOLVED = "/dev/block/sda24"
REMOTE_STAGING = "/tmp/sdm855-remapper-boot.img"
REMOTE_STAGING_BY_PROFILE = {
    "control": "/tmp/sdm855-remapper-boot.img",
    "read": "/tmp/sdm855-remapper-boot-read.img",
    "rollback": "/tmp/sdm855-remapper-boot-rollback.img",
}
DD_BLOCK_SIZE = 4096
DD_BLOCK_COUNT = BOOT_PREFIX_SIZE // DD_BLOCK_SIZE
SUBPROCESS_TIMEOUT_SEC = 300.0
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_CAPTURE_BYTES = BOOT_PREFIX_SIZE
CAPTURE_BLOCK_SIZE = DD_BLOCK_SIZE
# Physical rollback claims intentionally share the normal remapper namespace;
# the key is the current boot preimage/partition geometry, not this recovery
# owner's target or experiment identity.
EFFECT_CLAIM_SCHEMA = "sdm855-a90-v024-boot-prefix-physical-claim-v1"
EFFECT_CLAIM_PREFIX = "verification-024-boot-prefix-physical-"
CAPTURE_PREFIX = "verification-024-boot-torn-rollback-"

ROLLBACK_SHA256 = (
    "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb"
)
ROLLBACK_HASH = ROLLBACK_SHA256
ROLLBACK_SIZE = BOOT_PREFIX_SIZE
CONTROL_SHA256 = (
    "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247"
)
READ_SHA256 = (
    "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed"
)
KNOWN_V024_BOOT_HASHES = frozenset({ROLLBACK_SHA256, CONTROL_SHA256, READ_SHA256})
V024_PROFILE_HASHES = {
    "control": CONTROL_SHA256,
    "read": READ_SHA256,
    "rollback": ROLLBACK_SHA256,
}
V024_ALLOWED_PREDECESSORS = {
    "control": (ROLLBACK_SHA256,),
    "read": (CONTROL_SHA256,),
    # This is the canonical producer ordering (``sorted`` by the normal
    # remapper owner), not merely an unordered membership set.
    "rollback": (READ_SHA256, CONTROL_SHA256),
}
ROLLBACK_IMAGE = Path(
    "/home/temmie/dev/android-native-init-lab/workspace/private/inputs/"
    "boot_images/boot_linux_v2321_usb_clean_identity_rodata.img"
)
V024_ARTIFACT_RELATIVE_PATHS = {
    CONTROL_SHA256: Path(
        "evidence/private/verification-024-remapper-build-20260827-01/"
        "control/boot_linux_inline_remapper_control_v1.img"
    ),
    READ_SHA256: Path(
        "evidence/private/verification-024-remapper-build-20260827-01/"
        "read/boot_linux_inline_remapper_read_v1.img"
    ),
}

SOURCE_SCHEMA = "sdm855-a90-remapper-boot-flash-private-v1"
SOURCE_AMBIGUOUS_STATUS = "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
JOURNAL_SCHEMA = "sdm855-a90-boot-torn-rollback-recovery-private-v1"
PUBLIC_SCHEMA = "sdm855-a90-boot-torn-rollback-recovery-public-v1"
SOURCE_CLAIM_SCHEMA = "sdm855-a90-remapper-source-consumption-claim-v1"
SOURCE_CLAIM_PREFIX = "verification-024-remapper-source-consumed-"
EFFECT_STARTED_STATUS = "EFFECT_DISPATCH_STARTED"
READBACK_STATUS = "READBACK_VERIFIED"
PASS_STATUS = "PASS_ROLLBACK_READBACK_AND_CLEANUP"
ALREADY_STATUS = "ALREADY_ROLLBACK_VERIFIED"
PASS_ALREADY_STATUS = "PASS_ALREADY_ROLLBACK_AND_CLEANUP"
AMBIGUOUS_STATUS = "AMBIGUOUS_AFTER_EFFECT_RECONCILIATION_REQUIRED"
SOURCE_CLAIMED_STATUS = "SOURCE_CLAIMED_RECONCILIATION_REQUIRED"
EFFECT_CLAIMED_STATUS = "PHYSICAL_EFFECT_CLAIMED_RECONCILIATION_REQUIRED"
REFUSED_STATUS = "REFUSED_PRE_EFFECT"
RECONCILE_STATUS = "ROLLBACK_RECONCILIATION_REQUIRED"
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_JOURNAL_NAME_RE = re.compile(
    r"verification-024-remapper-boot-flash-(control|read|rollback)\.journal\.json\Z"
)


class RollbackRecoveryError(RuntimeError):
    """A refusal, ambiguity, or incomplete close of the recovery owner."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _reject_symlink_components(path: Path, label: str = "path") -> None:
    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise RollbackRecoveryError(f"{label} component must not be a symlink: {cursor}")
        if cursor == anchor:
            return
        cursor = cursor.parent


def _ensure_output_dirs(root: Path) -> tuple[Path, Path]:
    _reject_symlink_components(root, "output")
    private_dir = root / "evidence" / "private"
    public_dir = root / "evidence" / "manifests"
    _reject_symlink_components(private_dir, "output")
    _reject_symlink_components(public_dir, "output")
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    public_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(private_dir, 0o700)
    os.chmod(public_dir, 0o755)
    return private_dir, public_dir


def _refuse_existing(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise RollbackRecoveryError(f"output already exists; replay forbidden: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RollbackRecoveryError(
            f"output temporary already exists; replay forbidden: {temporary}"
        )


def _atomic_json(path: Path, value: object) -> bytes:
    """Write one private journal revision durably without following links."""

    _reject_symlink_components(path.parent, "journal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    data = json_bytes(value)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RollbackRecoveryError(f"journal temporary already exists: {temporary}")
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
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return data


def _create_initial_json(path: Path, value: object, mode: int = 0o600) -> bytes:
    """Claim the final journal inode before any target/device contact."""

    _reject_symlink_components(path.parent, "journal")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    data = json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RollbackRecoveryError("short initial journal write")
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


def _rollback_effect_identity(current_pre_hash: str, current_pre_size: int) -> tuple[dict[str, object], str]:
    """Return the shared source/experiment-independent boot-prefix key."""

    try:
        return boot_prefix_claim_identity(current_pre_hash, current_pre_size)
    except PhysicalClaimError as exc:
        raise RollbackRecoveryError(str(exc)) from exc


def _rollback_effect_claim_path(effect_key_sha256: str) -> Path:
    try:
        return boot_prefix_claim_path(Path(REPO_ROOT), effect_key_sha256)
    except PhysicalClaimError as exc:
        raise RollbackRecoveryError(str(exc)) from exc


def _create_rollback_effect_claim(
    claim_path: Path,
    *,
    identity: Mapping[str, object],
    effect_key_sha256: str,
    experiment_id: str,
    terminal: str,
) -> bytes:
    """Reserve one shared physical boot-prefix claim with final-path O_EXCL."""

    try:
        return create_boot_prefix_claim(
            claim_path,
            identity=identity,
            key_sha256=effect_key_sha256,
            experiment_id=experiment_id,
            provenance={
                "owner_kind": "torn-rollback-recovery",
                "terminal": terminal,
            },
        )
    except PhysicalClaimAlreadyExists as exc:
        raise RollbackRecoveryError(
            "rollback physical effect claim already exists; replay forbidden"
        ) from exc
    except PhysicalClaimError as exc:
        raise RollbackRecoveryError(str(exc)) from exc


def _rollback_staging_for_effect(source_semantic_sha256: str, effect_key_sha256: str) -> str:
    """Derive a source/effect-specific remote staging pathname."""

    if SHA256_RE.fullmatch(source_semantic_sha256) is None or SHA256_RE.fullmatch(effect_key_sha256) is None:
        raise RollbackRecoveryError("rollback staging derivation keys are not exact")
    staging_key = sha256(
        json_bytes(
            {
                "schema": "sdm855-a90-twrp-rollback-staging-v1",
                "source_semantic_sha256": source_semantic_sha256,
                "effect_key_sha256": effect_key_sha256,
            }
        )
    )
    return f"/tmp/sdm855-remapper-boot-rollback-{staging_key}.img"


def _write_public(path: Path, value: object) -> bytes:
    """Create one public redacted receipt with mode 0644."""

    _reject_symlink_components(path.parent, "manifest")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    data = json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RollbackRecoveryError("short public receipt write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return data


def _open_regular_nofollow(path: Path) -> int:
    _reject_symlink_components(path, "referenced journal")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags)


def _stable_source(path: Path) -> tuple[dict[str, object], bytes, str]:
    """Read and hash a regular source journal through one stable fd."""

    try:
        descriptor = _open_regular_nofollow(path)
    except OSError as exc:
        raise RollbackRecoveryError(f"referenced flash journal is unavailable: {path}") from exc
    try:
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise RollbackRecoveryError("referenced flash journal is not regular")
            data = bytearray()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_SOURCE_BYTES:
                    raise RollbackRecoveryError("referenced flash journal exceeds fixed bound")
            after = os.fstat(descriptor)
            identity_before = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            identity_after = (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if identity_before != identity_after or before.st_size != len(data):
                raise RollbackRecoveryError("referenced flash journal changed while being read")
        except OSError as exc:
            raise RollbackRecoveryError("referenced flash journal could not be read stably") from exc
    finally:
        os.close(descriptor)
    raw = bytes(data)
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RollbackRecoveryError(
                    f"referenced flash journal contains duplicate key: {key!r}"
                )
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> object:
        raise RollbackRecoveryError(
            f"referenced flash journal contains non-finite JSON constant: {value}"
        )

    try:
        source = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except RollbackRecoveryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RollbackRecoveryError("referenced flash journal is not valid JSON") from exc
    if not isinstance(source, dict):
        raise RollbackRecoveryError("referenced flash journal root is not an object")
    return source, raw, sha256(raw)


def _stable_source_identity(
    path: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    expected_identity: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return the validated source journal identity and repeat its hash check.

    The source claim is a one-way host-side consumption lock.  Re-reading the
    source through a no-follow descriptor immediately before creating that
    lock prevents a path replacement between initial validation and the
    effect boundary from being silently associated with the old hash.
    """

    _reject_symlink_components(path, "referenced journal")
    try:
        descriptor = _open_regular_nofollow(path)
    except OSError as exc:
        raise RollbackRecoveryError(
            f"referenced flash journal is unavailable: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RollbackRecoveryError("referenced flash journal is not regular")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise RollbackRecoveryError(
                    "referenced flash journal exceeds fixed bound"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        actual_hash = digest.hexdigest()
        if identity_before != identity_after or total != expected_size:
            raise RollbackRecoveryError(
                "referenced flash journal changed while being claimed"
            )
        if actual_hash != expected_sha256:
            raise RollbackRecoveryError(
                "referenced flash journal hash changed before claim"
            )
        identity = {
            "st_dev": before.st_dev,
            "st_ino": before.st_ino,
            "st_mode": before.st_mode,
            "st_size": before.st_size,
            "st_mtime_ns": before.st_mtime_ns,
            "st_ctime_ns": before.st_ctime_ns,
            "sha256": actual_hash,
        }
        if expected_identity is not None and dict(expected_identity) != identity:
            raise RollbackRecoveryError(
                "referenced flash journal identity changed before claim"
            )
        return identity
    except OSError as exc:
        raise RollbackRecoveryError(
            "referenced flash journal could not be read for claim"
        ) from exc
    finally:
        os.close(descriptor)


def _canonical_source_path(profile: str) -> Path:
    """Return the one fixed normal-flash journal path for ``profile``."""

    if profile not in V024_PROFILE_HASHES:
        raise RollbackRecoveryError("source profile is not a fixed V024 profile")
    fixed_root = Path(REPO_ROOT)
    _reject_symlink_components(fixed_root, "source journal")
    return (
        fixed_root.resolve(strict=False)
        / "evidence"
        / "private"
        / f"verification-024-remapper-boot-flash-{profile}.journal.json"
    )


def _source_claim_path(source_semantic_sha256: str) -> Path:
    """Return the fixed repository-root claim path for one semantic source."""

    if SHA256_RE.fullmatch(source_semantic_sha256) is None:
        raise RollbackRecoveryError(
            "source journal hash is not exact for consumption claim"
        )
    fixed_root = Path(REPO_ROOT)
    _reject_symlink_components(fixed_root, "source consumption claim")
    claim_dir = fixed_root.resolve(strict=False) / "evidence" / "private"
    _reject_symlink_components(claim_dir, "source consumption claim")
    claim_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(claim_dir, 0o700)
    claim = claim_dir / f"{SOURCE_CLAIM_PREFIX}{source_semantic_sha256}.claim.json"
    _reject_symlink_components(claim, "source consumption claim")
    return claim


def _require_source_claim_available(claim_path: Path) -> None:
    """Fail closed if this source hash has already been consumed or locked."""

    temporary = claim_path.with_name(claim_path.name + ".tmp")
    lock = claim_path.with_name(claim_path.name + ".lock")
    if claim_path.exists() or claim_path.is_symlink():
        raise RollbackRecoveryError(
            "source journal consumption claim already exists; replay forbidden"
        )
    if temporary.exists() or temporary.is_symlink():
        raise RollbackRecoveryError(
            "source journal consumption claim lock exists; replay forbidden"
        )
    if lock.exists() or lock.is_symlink():
        raise RollbackRecoveryError(
            "source journal consumption claim lock exists; replay forbidden"
        )


def _create_source_claim(
    claim_path: Path,
    *,
    source_path: Path,
    source_sha256: str,
    source_semantic_sha256: str,
    source_semantic_identity: Mapping[str, object],
    source_size: int,
    source_identity: Mapping[str, object],
    source_profile: str,
    experiment_id: str,
    terminal: str,
    claim_phase: str | None = None,
) -> bytes:
    """Create the immutable source-consumption claim with O_EXCL/no-follow.

    This is deliberately not an atomic replace.  A crash after creation must
    leave the claim present so a later invocation cannot replay the source.
    """

    _reject_symlink_components(claim_path.parent, "source consumption claim")
    temporary = claim_path.with_name(claim_path.name + ".tmp")
    lock = claim_path.with_name(claim_path.name + ".lock")
    if (
        claim_path.exists()
        or claim_path.is_symlink()
        or temporary.exists()
        or temporary.is_symlink()
        or lock.exists()
        or lock.is_symlink()
    ):
        raise RollbackRecoveryError(
            "source journal consumption claim already exists; replay forbidden"
        )
    data = json_bytes(
        {
            "schema": SOURCE_CLAIM_SCHEMA,
            "source_journal_path": str(source_path),
            "source_journal_sha256": source_sha256,
            "source_semantic_sha256": source_semantic_sha256,
            "key_sha256": source_semantic_sha256,
            "source_semantic_identity": dict(source_semantic_identity),
            "source_profile": source_profile,
            "source_journal_size": source_size,
            "source_journal_identity": dict(source_identity),
            "consumed_by_experiment_id": experiment_id,
            "terminal": terminal,
            "claim_phase": claim_phase or terminal,
            "effect_replayed": False,
            "created_utc": utc_now(),
        }
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(claim_path, flags, 0o600)
    except OSError as exc:
        raise RollbackRecoveryError(
            "source journal consumption claim could not be acquired"
        ) from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RollbackRecoveryError("short source consumption claim write")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    directory_fd = os.open(
        claim_path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return data


def _verify_source_claim(claim_path: Path, expected_data: bytes) -> None:
    """Re-read the O_EXCL source lease after fsync and prove exact bytes."""

    _reject_symlink_components(claim_path, "source consumption claim")
    try:
        descriptor = _open_regular_nofollow(claim_path)
    except OSError as exc:
        raise RollbackRecoveryError(
            "source journal consumption claim could not be re-opened durably"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != len(expected_data):
            raise RollbackRecoveryError(
                "source journal consumption claim has an unexpected size"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > len(expected_data):
                raise RollbackRecoveryError(
                    "source journal consumption claim exceeds fixed size"
                )
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise RollbackRecoveryError(
                "source journal consumption claim changed while being verified"
            )
        actual = b"".join(chunks)
        if total != len(expected_data) or actual != expected_data:
            raise RollbackRecoveryError(
                "source journal consumption claim bytes differ after fsync"
            )
    except OSError as exc:
        raise RollbackRecoveryError(
            "source journal consumption claim could not be read durably"
        ) from exc
    finally:
        os.close(descriptor)


def _path_under(path: Path, parent: Path, label: str) -> Path:
    _reject_symlink_components(path, label)
    _reject_symlink_components(parent, label)
    resolved = path.resolve(strict=False)
    parent_resolved = parent.resolve(strict=False)
    try:
        resolved.relative_to(parent_resolved)
    except ValueError as exc:
        raise RollbackRecoveryError(f"{label} must be under {parent_resolved}") from exc
    return resolved


def _source_path(root: Path, args: argparse.Namespace) -> Path:
    value = getattr(args, "flash_journal", None)
    if value is None:
        value = getattr(args, "journal", None)
    if value is None:
        value = getattr(args, "source_journal", None)
    if value is None:
        raise RollbackRecoveryError("an ambiguous V024 flash journal reference is required")
    path = Path(value)
    if not path.is_absolute():
        # A relative reference is interpreted as a basename within the fixed
        # private evidence directory; callers may also spell the full
        # ``evidence/private/...`` path.  The profile/path check below still
        # requires the canonical normal-flash journal basename.
        if not path.parts or path.parts[0] != "evidence":
            path = root / "evidence" / "private" / path
        else:
            path = root / path
    path = _path_under(path, root / "evidence" / "private", "referenced flash journal")
    # The source selector is only a spelling of one of the fixed producer
    # journals.  Reject arbitrary private-evidence paths before opening or
    # parsing them; the profile/path identity is part of the one-way claim.
    match = SOURCE_JOURNAL_NAME_RE.fullmatch(path.name)
    if match is None:
        raise RollbackRecoveryError(
            "referenced flash journal must be the canonical fixed V024 profile journal"
        )
    profile = match.group(1)
    if path != _canonical_source_path(profile):
        raise RollbackRecoveryError(
            "referenced flash journal must be the canonical fixed V024 profile journal"
        )
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RollbackRecoveryError(
            f"referenced flash journal temporary exists: {temporary}"
        )
    return path


def _validate_source(
    source: Mapping[str, object],
    *,
    source_path: Path | None = None,
) -> dict[str, object]:
    if source.get("schema") != SOURCE_SCHEMA:
        raise RollbackRecoveryError("referenced journal is not the V024 flash schema")
    if source.get("status") != SOURCE_AMBIGUOUS_STATUS:
        raise RollbackRecoveryError("referenced journal does not prove an ambiguous effect")
    if source.get("effect_replayed") is not False:
        raise RollbackRecoveryError(
            "referenced journal effect_replayed must be exact false"
        )
    if source.get("target_model") != TARGET_MODEL:
        raise RollbackRecoveryError("referenced journal target model is not the pinned A90")
    if source.get("target_device") != TARGET_DEVICE:
        raise RollbackRecoveryError("referenced journal target device is not the pinned A90")
    if source.get("target_serial_sha256") != TARGET_SERIAL_SHA256:
        raise RollbackRecoveryError("referenced journal target serial hash is not pinned")
    if source.get("boot_alias") != BOOT_BLOCK_ALIAS:
        raise RollbackRecoveryError("referenced journal boot alias is not the pinned alias")
    if source.get("boot_node") != BOOT_BLOCK_RESOLVED:
        raise RollbackRecoveryError("referenced journal boot node is not the pinned node")
    profile = source.get("profile")
    if not isinstance(profile, str) or profile not in V024_PROFILE_HASHES:
        raise RollbackRecoveryError("referenced journal profile is not a fixed V024 profile")
    if source_path is not None:
        canonical = _canonical_source_path(profile)
        if source_path != canonical:
            raise RollbackRecoveryError(
                "referenced journal path is not the canonical fixed V024 profile journal"
            )
    if source.get("image_sha256") != V024_PROFILE_HASHES[profile]:
        raise RollbackRecoveryError("referenced journal profile/image hash is inconsistent")
    if source.get("image_size") != BOOT_PREFIX_SIZE:
        raise RollbackRecoveryError("referenced journal image size is not complete")
    expected_allowed = list(V024_ALLOWED_PREDECESSORS[profile])
    allowed = source.get("allowed_predecessors")
    if type(allowed) is not list or allowed != expected_allowed:
        raise RollbackRecoveryError(
            "referenced journal predecessor matrix is not exact"
        )
    try:
        source_staging = REMOTE_STAGING_BY_PROFILE[profile]
    except KeyError as exc:
        raise RollbackRecoveryError("referenced journal profile has no fixed staging path") from exc
    if source.get("remote_staging") != source_staging:
        raise RollbackRecoveryError("referenced journal staging path is not fixed for its profile")
    if source.get("remote_staging_sha256") != V024_PROFILE_HASHES[profile]:
        raise RollbackRecoveryError(
            "referenced journal staging hash is not the fixed intended image"
        )
    if source.get("remote_staging_size") != BOOT_PREFIX_SIZE:
        raise RollbackRecoveryError("referenced journal staging size is not complete")
    expected_effect_argv = [
        "dd",
        f"if={source_staging}",
        f"of={BOOT_BLOCK_RESOLVED}",
        "bs=4096",
        f"count={BOOT_PREFIX_SIZE // 4096}",
        "conv=fsync",
    ]
    if source.get("effect_argv") != expected_effect_argv:
        raise RollbackRecoveryError("referenced journal effect command is not the fixed boot write")
    if (
        source.get("effect_armed") is not True
        or source.get("effect_dispatched") is not True
    ):
        raise RollbackRecoveryError("referenced journal does not prove its effect was armed")
    write_count = source.get("write_count")
    if isinstance(write_count, bool) or not isinstance(write_count, int) or write_count != 1:
        raise RollbackRecoveryError("referenced journal write_count is not exactly one")
    if source.get("current_state") != "UNKNOWN":
        raise RollbackRecoveryError(
            "referenced journal lacks explicit UNKNOWN current state"
        )
    if source.get("staging_cleanup_deferred") is not True:
        raise RollbackRecoveryError("referenced journal does not defer staging cleanup")
    if source.get("reconcile_required") is not True:
        raise RollbackRecoveryError("referenced journal does not require reconciliation")
    for key, expected in {
        "effect_ambiguous": True,
        "automatic_retries": False,
        "reboot_dispatched": False,
        "partition_writes": True,
        "staging_attempted": True,
        "staging_attempt_count": 1,
        "staging_dispatch_count": 1,
        "staging_status": "STAGING_PUSH_RETURNED",
        "pre_staging_removed": True,
        "pre_cleanup_revalidated": True,
        "pre_push_revalidated": True,
        "staging_removed": False,
        "post_staging_predecessor_revalidated": True,
        "pre_effect_revalidated": True,
    }.items():
        actual = source.get(key)
        if isinstance(expected, bool):
            exact = actual is expected
        elif isinstance(expected, int):
            exact = type(actual) is int and actual == expected
        else:
            exact = actual == expected
        if not exact:
            raise RollbackRecoveryError(
                f"referenced journal {key} is not the exact ambiguous value"
            )
    pre_hash_obj = source.get("predecessor_sha256")
    if not isinstance(pre_hash_obj, str) or SHA256_RE.fullmatch(pre_hash_obj) is None:
        raise RollbackRecoveryError("referenced journal lacks an exact predecessor hash")
    if pre_hash_obj not in V024_ALLOWED_PREDECESSORS[profile]:
        raise RollbackRecoveryError(
            "referenced journal predecessor is not allowed for its profile"
        )
    pre_size = source.get("predecessor_size")
    if pre_size != BOOT_PREFIX_SIZE:
        raise RollbackRecoveryError("referenced journal pre-hash size is not complete")
    if source.get("post_staging_predecessor_sha256") != pre_hash_obj:
        raise RollbackRecoveryError(
            "referenced journal post-staging predecessor hash differs"
        )
    if source.get("post_staging_predecessor_size") != BOOT_PREFIX_SIZE:
        raise RollbackRecoveryError(
            "referenced journal post-staging predecessor size is not complete"
        )

    # A returned guarded receipt is optional for an ambiguous transport
    # failure, but if it exists it must be the exact parsed receipt and all
    # post-dispatch projections must agree with the fixed pre-effect contract.
    projection_keys = (
        "post_dispatch_predecessor_sha256",
        "post_dispatch_predecessor_size",
        "post_dispatch_staging_sha256",
        "post_dispatch_staging_size",
    )
    guarded_receipt = source.get("guarded_effect_receipt")
    projection_present = any(key in source for key in projection_keys)
    if guarded_receipt is None:
        if projection_present:
            raise RollbackRecoveryError(
                "referenced journal has post-dispatch projections without a receipt"
            )
    else:
        if not isinstance(guarded_receipt, Mapping):
            raise RollbackRecoveryError("referenced journal guarded receipt is not an object")
        if set(guarded_receipt) != {"schema", "guard", "dd_result", "write_count"}:
            raise RollbackRecoveryError("referenced journal guarded receipt fields are not exact")
        if guarded_receipt.get("schema") != "sdm855-a90-remapper-guarded-effect-v1":
            raise RollbackRecoveryError("referenced journal guarded receipt schema is not exact")
        if type(guarded_receipt.get("write_count")) is not int or guarded_receipt.get("write_count") != 1:
            raise RollbackRecoveryError("referenced journal guarded receipt write count is not exact")
        guard = guarded_receipt.get("guard")
        result = guarded_receipt.get("dd_result")
        if not isinstance(guard, Mapping) or not isinstance(result, Mapping):
            raise RollbackRecoveryError("referenced journal guarded receipt sections are missing")
        if set(guard) != {"current_sha256", "current_size", "staging_sha256", "staging_size"}:
            raise RollbackRecoveryError("referenced journal guarded receipt guard fields are not exact")
        if guard != {
            "current_sha256": pre_hash_obj,
            "current_size": str(BOOT_PREFIX_SIZE),
            "staging_sha256": V024_PROFILE_HASHES[profile],
            "staging_size": str(BOOT_PREFIX_SIZE),
        }:
            raise RollbackRecoveryError("referenced journal guarded receipt guard values differ")
        if result != {"rc": "0", "count": str(BOOT_PREFIX_SIZE // 4096)}:
            raise RollbackRecoveryError("referenced journal guarded receipt dd result differs")
        if not projection_present or any(key not in source for key in projection_keys):
            raise RollbackRecoveryError(
                "referenced journal guarded receipt projections are incomplete"
            )
        if {
            "post_dispatch_predecessor_sha256": source.get("post_dispatch_predecessor_sha256"),
            "post_dispatch_predecessor_size": source.get("post_dispatch_predecessor_size"),
            "post_dispatch_staging_sha256": source.get("post_dispatch_staging_sha256"),
            "post_dispatch_staging_size": source.get("post_dispatch_staging_size"),
        } != {
            "post_dispatch_predecessor_sha256": pre_hash_obj,
            "post_dispatch_predecessor_size": BOOT_PREFIX_SIZE,
            "post_dispatch_staging_sha256": V024_PROFILE_HASHES[profile],
            "post_dispatch_staging_size": BOOT_PREFIX_SIZE,
        }:
            raise RollbackRecoveryError("referenced journal post-dispatch projections differ")
    semantic = {
        "schema": SOURCE_SCHEMA,
        "source_journal_path": str(
            _canonical_source_path(profile)
            if source_path is None
            else source_path
        ),
        "profile": profile,
        "allowed_predecessors": expected_allowed,
        "predecessor_sha256": pre_hash_obj,
        "predecessor_size": BOOT_PREFIX_SIZE,
        "image_sha256": V024_PROFILE_HASHES[profile],
        "image_size": BOOT_PREFIX_SIZE,
        "remote_staging": source_staging,
        "remote_staging_sha256": V024_PROFILE_HASHES[profile],
        "remote_staging_size": BOOT_PREFIX_SIZE,
        "post_staging_predecessor_sha256": pre_hash_obj,
        "post_staging_predecessor_size": BOOT_PREFIX_SIZE,
        "effect_argv": expected_effect_argv,
    }
    semantic_data = json_bytes(semantic)
    semantic_sha256 = sha256(semantic_data)
    evidence = {
        "status": str(source["status"]),
        "profile": profile,
        "allowed_predecessors": expected_allowed,
        "predecessor_sha256": pre_hash_obj,
        "predecessor_size": BOOT_PREFIX_SIZE,
        "image_sha256": V024_PROFILE_HASHES[profile],
        "image_size": BOOT_PREFIX_SIZE,
        "remote_staging": source_staging,
        "remote_staging_sha256": V024_PROFILE_HASHES[profile],
        "remote_staging_size": BOOT_PREFIX_SIZE,
        "post_staging_predecessor_sha256": pre_hash_obj,
        "post_staging_predecessor_size": BOOT_PREFIX_SIZE,
        "effect_argv": expected_effect_argv,
        "guarded_effect_receipt": guarded_receipt,
        "semantic_identity": semantic,
        "semantic_sha256": semantic_sha256,
        "write_count": 1,
        "effect_replayed": False,
        "effect_armed": True,
        "current_state": "unknown",
        "pre_hash_sha256": pre_hash_obj,
        "pre_hash_size": BOOT_PREFIX_SIZE,
    }
    # Preserve optional post-dispatch measurements only when the producer
    # durably returned and parsed its guarded receipt.  An ambiguous transport
    # failure before that receipt must not acquire fabricated measurements.
    if guarded_receipt is not None:
        evidence.update(
            {
                "post_dispatch_predecessor_sha256": source[
                    "post_dispatch_predecessor_sha256"
                ],
                "post_dispatch_predecessor_size": source[
                    "post_dispatch_predecessor_size"
                ],
                "post_dispatch_staging_sha256": source[
                    "post_dispatch_staging_sha256"
                ],
                "post_dispatch_staging_size": source["post_dispatch_staging_size"],
            }
        )
    return evidence


def run_checked(argv: Sequence[str]) -> str:
    """Run the fixed literal adb transport with one finite bound."""

    if not argv or argv[0] != ADB:
        raise RollbackRecoveryError("torn rollback accepts only the fixed adb executable")
    try:
        result = subprocess.run(
            list(argv),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired as exc:
        raise RollbackRecoveryError(
            f"fixed adb command timed out after {SUBPROCESS_TIMEOUT_SEC}s"
        ) from exc
    if result.returncode != 0:
        raise RollbackRecoveryError(
            f"fixed adb command failed: rc={result.returncode}; stderr={result.stderr.strip()!r}"
        )
    return result.stdout.replace("\r", "")


def run_capture(argv: Sequence[str]) -> bytes:
    """Run one bounded binary ADB exec-out capture through the fixed binary."""

    if not argv or argv[0] != ADB:
        raise RollbackRecoveryError("torn rollback accepts only the fixed adb executable")
    try:
        process = subprocess.Popen(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise RollbackRecoveryError(f"bounded boot capture could not start: {exc}") from exc
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
    except BaseException:
        try:
            process.kill()
            process.wait(timeout=5.0)
        except BaseException:
            pass
        selector.close()
        raise RollbackRecoveryError("bounded boot capture stdout is not selectable")
    deadline = time.monotonic() + SUBPROCESS_TIMEOUT_SEC
    data = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RollbackRecoveryError("bounded boot capture timed out")
            events = selector.select(min(remaining, 0.25))
            if not events:
                if process.poll() is not None:
                    # There may still be a final readable/EOF event; loop
                    # once more with the same bounded deadline to drain it.
                    continue
                continue
            # Read at most one byte beyond the fixed bound.  This proves an
            # oversized capture without ever buffering an attacker-controlled
            # stream in host memory.
            remaining_bytes = MAX_CAPTURE_BYTES + 1 - len(data)
            chunk = os.read(process.stdout.fileno(), min(1024 * 1024, remaining_bytes))
            if chunk:
                data.extend(chunk)
                if len(data) > MAX_CAPTURE_BYTES:
                    raise RollbackRecoveryError(
                        "bounded boot capture exceeded fixed size"
                    )
                continue
            if process.poll() is not None:
                break
        return_code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        try:
            process.kill()
            process.wait(timeout=5.0)
        except BaseException:
            pass
        raise RollbackRecoveryError("bounded boot capture timed out") from exc
    except BaseException:
        try:
            process.kill()
            process.wait(timeout=5.0)
        except BaseException:
            pass
        raise
    finally:
        selector.close()
    if return_code != 0:
        raise RollbackRecoveryError(
            f"bounded boot capture failed with rc={return_code}"
        )
    return bytes(data)


def _adb_shell(serial: str, command: str) -> str:
    return run_checked((ADB, "-s", serial, "shell", command))


def _parse_sha256(output: str) -> str:
    values = re.findall(r"(?m)^([0-9a-f]{64})(?:\s|$)", output)
    if len(values) != 1:
        raise RollbackRecoveryError("expected exactly one boot-prefix SHA-256")
    return values[0]


def _parse_size(output: str) -> int:
    values = [line.strip() for line in output.splitlines() if line.strip()]
    if len(values) != 1 or re.fullmatch(r"[0-9]+", values[0]) is None:
        raise RollbackRecoveryError("expected exactly one complete boot-prefix size")
    return int(values[0], 10)


def _boot_hash(serial: str) -> str:
    return _parse_sha256(
        _adb_shell(
            serial,
            f"dd if={BOOT_BLOCK_RESOLVED} bs={DD_BLOCK_SIZE} "
            f"count={DD_BLOCK_COUNT} 2>/dev/null | sha256sum",
        )
    )


def _boot_size(serial: str) -> int:
    return _parse_size(
        _adb_shell(
            serial,
            f"dd if={BOOT_BLOCK_RESOLVED} bs={DD_BLOCK_SIZE} "
            f"count={DD_BLOCK_COUNT} 2>/dev/null | wc -c",
        )
    )


def _validate_current_source_state(
    current_hash: str,
    current_size: int,
    source_evidence: Mapping[str, object],
) -> None:
    """Reject a complete known boot that cannot follow the source journal.

    An unknown prefix is the only state that remains eligible for the torn
    staging path.  Known rollback/control/read prefixes are accepted only
    when they are the source predecessor, the source's intended image, or
    the fixed rollback terminal.  This prevents an ambiguous control source
    from silently consuming a later READ state, for example.
    """

    if current_size != BOOT_PREFIX_SIZE:
        raise RollbackRecoveryError("current boot prefix is not complete")
    if current_hash not in KNOWN_V024_BOOT_HASHES:
        return
    predecessor = source_evidence.get("predecessor_sha256")
    intended = source_evidence.get("image_sha256")
    possible = {ROLLBACK_SHA256, predecessor, intended}
    if current_hash not in possible:
        raise RollbackRecoveryError(
            "current complete V024 boot is not causally possible for this source"
        )


def _remote_hash(serial: str, remote_staging: str) -> str:
    return _parse_sha256(_adb_shell(serial, f"sha256sum {remote_staging}"))


def _remote_size(serial: str, remote_staging: str) -> int:
    return _parse_size(_adb_shell(serial, f"wc -c < {remote_staging}"))


def _require_exact_twrp(endpoint: AdbEndpoint) -> None:
    model = _adb_shell(endpoint.serial, "getprop ro.product.model").strip()
    device = _adb_shell(endpoint.serial, "getprop ro.product.device").strip()
    if model != TARGET_MODEL or device != TARGET_DEVICE:
        raise RollbackRecoveryError(
            f"bound endpoint product identity is not exact: model={model!r} device={device!r}"
        )
    help_text = _adb_shell(endpoint.serial, "twrp --help 2>&1")
    if "TWRP openrecoveryscript command line tool" not in help_text:
        raise RollbackRecoveryError("bound endpoint is not the expected TWRP CLI")
    if f"TWRP version {TWRP_VERSION}" not in help_text:
        raise RollbackRecoveryError("bound endpoint TWRP version differs from pinned build")
    resolved = _adb_shell(endpoint.serial, f"readlink -f {BOOT_BLOCK_ALIAS}").strip()
    if resolved != BOOT_BLOCK_RESOLVED:
        raise RollbackRecoveryError(f"boot node resolved unexpectedly: {resolved!r}")


def _revalidate_recovery(initial: AdbEndpoint | None = None) -> AdbEndpoint:
    """Re-enumerate and bind the exact Recovery endpoint immediately before mutation."""

    endpoint = select_exact_recovery(
        ADB,
        run=run_checked,
        expected_serial_sha256=TARGET_SERIAL_SHA256,
    )
    if endpoint.state != "recovery" or endpoint.serial_sha256 != TARGET_SERIAL_SHA256:
        raise RollbackRecoveryError("exact pinned A90 Recovery endpoint was not bound")
    if initial is not None and (
        endpoint.serial != initial.serial
        or endpoint.serial_sha256 != initial.serial_sha256
    ):
        raise RollbackRecoveryError("Recovery endpoint changed during torn-write recovery")
    _require_exact_twrp(endpoint)
    return endpoint


def _cleanup_remote(serial: str, remote_staging: str) -> tuple[bool, str | None]:
    try:
        _adb_shell(serial, f"rm -f {remote_staging}")
    except BaseException as exc:
        return False, f"{type(exc).__name__}: {exc}"
    try:
        marker = _adb_shell(
            serial,
            f"if [ -e {remote_staging} ] || [ -L {remote_staging} ]; then "
            "echo present; else echo absent; fi",
        ).strip()
    except BaseException as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if marker != "absent":
        return False, f"remote staging cleanup marker was {marker!r}"
    return True, None


def _stable_image_digest(path: Path) -> tuple[int, str]:
    _reject_symlink_components(path, "rollback image")
    try:
        descriptor = _open_regular_nofollow(path)
    except OSError as exc:
        raise RollbackRecoveryError(f"pinned rollback image is unavailable: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RollbackRecoveryError("pinned rollback image is not regular")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or total != BOOT_PREFIX_SIZE:
            raise RollbackRecoveryError("pinned rollback image changed or has incomplete size")
        return total, digest.hexdigest()
    finally:
        os.close(descriptor)


def _stable_artifact_bytes(path: Path, expected_sha256: str) -> bytes:
    """Read one fixed V024 artifact through a stable no-follow descriptor."""

    _reject_symlink_components(path, "V024 boot artifact")
    try:
        descriptor = _open_regular_nofollow(path)
    except OSError as exc:
        raise RollbackRecoveryError(f"V024 boot artifact is unavailable: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != BOOT_PREFIX_SIZE:
            raise RollbackRecoveryError("V024 boot artifact has incomplete size")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > BOOT_PREFIX_SIZE:
                raise RollbackRecoveryError("V024 boot artifact exceeds fixed size")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(data) != BOOT_PREFIX_SIZE:
            raise RollbackRecoveryError("V024 boot artifact changed while being read")
    finally:
        os.close(descriptor)
    result = bytes(data)
    if sha256(result) != expected_sha256:
        raise RollbackRecoveryError("V024 boot artifact hash differs from its fixed map")
    return result


def _artifact_path_for_hash(root: Path, image_sha256: str) -> Path:
    if image_sha256 == ROLLBACK_SHA256:
        return ROLLBACK_IMAGE
    relative = V024_ARTIFACT_RELATIVE_PATHS.get(image_sha256)
    if relative is None:
        raise RollbackRecoveryError("source predecessor/image is not a fixed V024 artifact")
    path = root / relative
    _reject_symlink_components(path, "V024 boot artifact")
    return path


def _write_private_capture(path: Path, data: bytes) -> None:
    """Persist one bounded private capture without replacing an inode."""

    _reject_symlink_components(path.parent, "boot-prefix capture")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
                raise RollbackRecoveryError("short private boot-prefix capture write")
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


def _capture_unknown_preimage(
    root: Path,
    experiment_id: str,
    serial: str,
    current_pre_hash: str,
    current_pre_size: int,
    source_evidence: Mapping[str, object],
) -> dict[str, object]:
    """Capture/validate a torn prefix and prove predecessor/intended mixture."""

    if current_pre_hash in KNOWN_V024_BOOT_HASHES:
        raise RollbackRecoveryError("known V024 boot does not require unknown capture")
    if current_pre_size != BOOT_PREFIX_SIZE:
        raise RollbackRecoveryError("unknown current boot prefix is not complete")
    predecessor = source_evidence.get("predecessor_sha256")
    intended = source_evidence.get("image_sha256")
    if (
        not isinstance(predecessor, str)
        or not isinstance(intended, str)
        or SHA256_RE.fullmatch(predecessor) is None
        or SHA256_RE.fullmatch(intended) is None
    ):
        raise RollbackRecoveryError("unknown preimage source hashes are not exact")
    predecessor_bytes = _stable_artifact_bytes(
        _artifact_path_for_hash(root, predecessor), predecessor
    )
    intended_bytes = _stable_artifact_bytes(
        _artifact_path_for_hash(root, intended), intended
    )
    captured = run_capture(
        (
            ADB,
            "-s",
            serial,
            "exec-out",
            f"dd if={BOOT_BLOCK_RESOLVED} bs={CAPTURE_BLOCK_SIZE} "
            f"count={DD_BLOCK_COUNT} 2>/dev/null",
        )
    )
    if not isinstance(captured, bytes) or len(captured) != BOOT_PREFIX_SIZE:
        raise RollbackRecoveryError("unknown boot capture size is not exact")
    captured_hash = sha256(captured)
    if captured_hash != current_pre_hash:
        raise RollbackRecoveryError(
            "device-before and host boot capture hashes differ"
        )
    device_after_hash = _boot_hash(serial)
    device_after_size = _boot_size(serial)
    if (
        device_after_hash != current_pre_hash
        or device_after_size != current_pre_size
    ):
        raise RollbackRecoveryError(
            "device-before and device-after boot prefix hashes differ"
        )
    allowed_blocks = 0
    for offset in range(0, BOOT_PREFIX_SIZE, CAPTURE_BLOCK_SIZE):
        block = captured[offset : offset + CAPTURE_BLOCK_SIZE]
        if block == predecessor_bytes[offset : offset + CAPTURE_BLOCK_SIZE] or block == intended_bytes[offset : offset + CAPTURE_BLOCK_SIZE]:
            allowed_blocks += 1
            continue
        raise RollbackRecoveryError(
            f"unknown boot prefix contains unrelated block at offset {offset}"
        )
    capture_path = (
        root
        / "evidence"
        / "private"
        / f"{CAPTURE_PREFIX}{experiment_id}.current-boot-prefix.bin"
    )
    _write_private_capture(capture_path, captured)
    return {
        "capture_path": str(capture_path),
        "capture_sha256": captured_hash,
        "capture_size": len(captured),
        "device_before_sha256": current_pre_hash,
        "device_before_size": current_pre_size,
        "host_capture_sha256": captured_hash,
        "host_capture_size": len(captured),
        "device_after_sha256": device_after_hash,
        "device_after_size": device_after_size,
        "block_size": CAPTURE_BLOCK_SIZE,
        "block_count": DD_BLOCK_COUNT,
        "allowed_block_count": allowed_blocks,
        "mixture_valid": True,
        "predecessor_sha256": predecessor,
        "intended_sha256": intended,
    }


def _guarded_rollback_command(
    remote_staging: str,
    expected_predecessor_sha256: str,
    expected_staging_sha256: str,
    expected_predecessor_size: int,
) -> str:
    """Guard current/staging bytes and perform the sole rollback dd."""

    if SHA256_RE.fullmatch(expected_predecessor_sha256) is None or SHA256_RE.fullmatch(expected_staging_sha256) is None:
        raise RollbackRecoveryError("rollback guarded-effect hashes are not exact")
    return (
        "set -e; "
        f"current_hash=$(dd if={BOOT_BLOCK_RESOLVED} bs={DD_BLOCK_SIZE} "
        f"count={DD_BLOCK_COUNT} 2>/dev/null | sha256sum | cut -d' ' -f1); "
        f"current_size=$(dd if={BOOT_BLOCK_RESOLVED} bs={DD_BLOCK_SIZE} "
        f"count={DD_BLOCK_COUNT} 2>/dev/null | wc -c); "
        f"staging_hash=$(sha256sum {remote_staging} | cut -d' ' -f1); "
        f"staging_size=$(wc -c < {remote_staging}); "
        f"if [ \"$current_hash\" = \"{expected_predecessor_sha256}\" ] "
        f"&& [ \"$current_size\" = \"{expected_predecessor_size}\" ] "
        f"&& [ \"$staging_hash\" = \"{expected_staging_sha256}\" ] "
        f"&& [ \"$staging_size\" = \"{BOOT_PREFIX_SIZE}\" ]; then "
        "printf 'A90V024 GUARD_PASS current_sha256=%s current_size=%s "
        "staging_sha256=%s staging_size=%s\\n' \"$current_hash\" "
        "\"$current_size\" \"$staging_hash\" \"$staging_size\"; "
        f"dd if={remote_staging} of={BOOT_BLOCK_RESOLVED} "
        f"bs={DD_BLOCK_SIZE} count={DD_BLOCK_COUNT} conv=fsync; "
        "dd_rc=$?; printf 'A90V024 DD_RESULT rc=%s count=%s\\n' \"$dd_rc\" "
        f"\"{DD_BLOCK_COUNT}\"; exit \"$dd_rc\"; "
        "else printf 'A90V024 GUARD_FAIL current_sha256=%s current_size=%s "
        "staging_sha256=%s staging_size=%s\\n' \"$current_hash\" "
        "\"$current_size\" \"$staging_hash\" \"$staging_size\"; exit 42; fi"
    )


def _parse_guarded_rollback_receipt(
    output: str,
    *,
    expected_predecessor_sha256: str,
    expected_staging_sha256: str,
    expected_predecessor_size: int,
) -> dict[str, object]:
    lines = [line.strip() for line in output.replace("\r", "").splitlines() if line.strip()]
    guard_lines = [line for line in lines if line.startswith("A90V024 GUARD_PASS ")]
    dd_lines = [line for line in lines if line.startswith("A90V024 DD_RESULT ")]
    if len(lines) != 2 or len(guard_lines) != 1 or len(dd_lines) != 1:
        raise RollbackRecoveryError("rollback guarded receipt is not exactly one guard and one dd result")

    def parse_fields(line: str, prefix: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        for token in line[len(prefix) :].split():
            if "=" not in token:
                raise RollbackRecoveryError("rollback guarded receipt field is malformed")
            key, value = token.split("=", 1)
            if not key or not value or key in fields:
                raise RollbackRecoveryError("rollback guarded receipt field is duplicate or empty")
            fields[key] = value
        return fields

    guard = parse_fields(guard_lines[0], "A90V024 GUARD_PASS ")
    if set(guard) != {"current_sha256", "current_size", "staging_sha256", "staging_size"}:
        raise RollbackRecoveryError("rollback guarded receipt guard fields are not exact")
    if guard != {
        "current_sha256": expected_predecessor_sha256,
        "current_size": str(expected_predecessor_size),
        "staging_sha256": expected_staging_sha256,
        "staging_size": str(BOOT_PREFIX_SIZE),
    }:
        raise RollbackRecoveryError("rollback guarded receipt guard values differ")
    result = parse_fields(dd_lines[0], "A90V024 DD_RESULT ")
    if result != {"rc": "0", "count": str(DD_BLOCK_COUNT)}:
        raise RollbackRecoveryError("rollback guarded receipt dd result is not exact")
    return {
        "schema": "sdm855-a90-twrp-rollback-guarded-effect-v1",
        "guard": guard,
        "dd_result": result,
        "write_count": 1,
    }


def _expected_target() -> dict[str, object]:
    return {
        "model": TARGET_MODEL,
        "device": TARGET_DEVICE,
        "twrp_version": TWRP_VERSION,
        "serial_sha256": TARGET_SERIAL_SHA256,
        "boot_alias": BOOT_BLOCK_ALIAS,
        "boot_node": BOOT_BLOCK_RESOLVED,
    }


def _public_manifest(
    *,
    experiment_id: str,
    started: str,
    completed: str,
    status: str,
    target: Mapping[str, object] | None,
    target_verified: bool,
    source_sha256: str,
    source_size: int,
    source_semantic_sha256: str,
    source_profile: str,
    journal_data: bytes,
    current_pre_hash: str | None,
    current_pre_size: int | None,
    write_count: int,
    cleanup_proved: bool,
    error: str | None,
    source_claim_data: bytes | None = None,
    source_claim_attempted: bool = False,
    source_claimed: bool = False,
    preimage_evidence: Mapping[str, object] | None = None,
    effect_claim_key_sha256: str | None = None,
    effect_claim_data: bytes | None = None,
    effect_claim_attempted: bool = False,
    effect_claimed: bool = False,
) -> dict[str, object]:
    actual = target if target_verified and target is not None else {}
    return {
        "schema": PUBLIC_SCHEMA,
        "experiment_id": experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "status": status,
        "target_verified": target_verified,
        "target_evaluation": "VERIFIED" if target_verified else "NOT_EVALUATED",
        "target": {
            "model": actual.get("model"),
            "device": actual.get("device"),
            "twrp_version": actual.get("twrp_version"),
            "serial_sha256": actual.get("serial_sha256"),
            "status": "VERIFIED" if target_verified else "NOT_EVALUATED",
        },
        "expected_target": _expected_target(),
        "source_flash_journal_sha256": source_sha256,
        "source_flash_journal_size": source_size,
        "source_consumption": {
            "claimed": source_claimed or source_claim_data is not None,
            "attempted": source_claim_attempted,
            "claim_sha256": (
                sha256(source_claim_data) if source_claim_data is not None else None
            ),
            "claim_size": len(source_claim_data) if source_claim_data is not None else None,
            "key_sha256": source_semantic_sha256,
            "semantic_sha256": source_semantic_sha256,
            "claim_key_sha256": source_semantic_sha256,
            "source_journal_sha256": source_sha256,
            "source_journal_size": source_size,
            "source_profile": source_profile,
        },
        "effect": {
            "command": "fixed boot-prefix rollback dd",
            "transport": ADB,
            "write_count": write_count,
            "effect_replayed": False,
            "partition": BOOT_BLOCK_RESOLVED,
        },
        "current_pre_hash_sha256": current_pre_hash,
        "current_pre_hash_size": current_pre_size,
        "rollback_sha256": ROLLBACK_SHA256,
        "rollback_size": BOOT_PREFIX_SIZE,
        "cleanup_proved": cleanup_proved,
        "partition_writes": write_count,
        "preimage_evidence": {
            key: preimage_evidence.get(key)
            for key in (
                "capture_sha256",
                "capture_size",
                "device_before_sha256",
                "device_before_size",
                "host_capture_sha256",
                "host_capture_size",
                "device_after_sha256",
                "device_after_size",
                "block_size",
                "block_count",
                "allowed_block_count",
                "mixture_valid",
            )
            if preimage_evidence is not None and key in preimage_evidence
        },
        "physical_effect_claim": {
            "claimed": effect_claimed or effect_claim_data is not None,
            "attempted": effect_claim_attempted,
            "key_sha256": effect_claim_key_sha256,
            "claim_sha256": (
                sha256(effect_claim_data) if effect_claim_data is not None else None
            ),
            "claim_size": len(effect_claim_data) if effect_claim_data is not None else None,
        },
        # Failure details remain private; the public receipt exposes only a
        # stable exception class so command/serial text cannot leak.
        "error_type": error.split(":", 1)[0] if isinstance(error, str) and error else None,
        "private_receipt_sha256": sha256(journal_data),
        "private_receipt_size": len(journal_data),
        "raw_serial_omitted": True,
        "raw_commands_omitted": True,
    }


def _publish(
    manifest_path: Path,
    *,
    experiment_id: str,
    started: str,
    status: str,
    target: Mapping[str, object] | None,
    target_verified: bool,
    source_sha256: str,
    source_size: int,
    source_semantic_sha256: str,
    source_profile: str,
    journal_data: bytes,
    current_pre_hash: str | None,
    current_pre_size: int | None,
    write_count: int,
    cleanup_proved: bool,
    error: str | None,
    source_claim_data: bytes | None = None,
    source_claim_attempted: bool = False,
    source_claimed: bool = False,
    preimage_evidence: Mapping[str, object] | None = None,
    effect_claim_key_sha256: str | None = None,
    effect_claim_data: bytes | None = None,
    effect_claim_attempted: bool = False,
    effect_claimed: bool = False,
) -> bytes:
    manifest = _public_manifest(
        experiment_id=experiment_id,
        started=started,
        completed=utc_now(),
        status=status,
        target=target,
        target_verified=target_verified,
        source_sha256=source_sha256,
        source_size=source_size,
        source_semantic_sha256=source_semantic_sha256,
        source_profile=source_profile,
        journal_data=journal_data,
        current_pre_hash=current_pre_hash,
        current_pre_size=current_pre_size,
        write_count=write_count,
        cleanup_proved=cleanup_proved,
        error=error,
        source_claim_data=source_claim_data,
        source_claim_attempted=source_claim_attempted,
        source_claimed=source_claimed,
        preimage_evidence=preimage_evidence,
        effect_claim_key_sha256=effect_claim_key_sha256,
        effect_claim_data=effect_claim_data,
        effect_claim_attempted=effect_claim_attempted,
        effect_claimed=effect_claimed,
    )
    return _write_public(manifest_path, manifest)


def _output_paths(root: Path, experiment_id: str) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise RollbackRecoveryError("invalid experiment ID")
    private_dir, public_dir = _ensure_output_dirs(root)
    journal = private_dir / f"verification-024-boot-torn-rollback-{experiment_id}.journal.json"
    manifest = public_dir / f"verification-024-boot-torn-rollback-{experiment_id}.manifest.json"
    _reject_symlink_components(journal, "journal")
    _reject_symlink_components(manifest, "manifest")
    _refuse_existing(journal)
    _refuse_existing(manifest)
    return journal, manifest


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    """Run the fixed mechanical torn-write recovery transaction."""

    if not bool(getattr(args, "execute", False)):
        raise RollbackRecoveryError("torn-write rollback requires explicit --execute")
    experiment_id = getattr(args, "experiment_id", None)
    if not isinstance(experiment_id, str) or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise RollbackRecoveryError("invalid experiment ID")
    if hasattr(args, "adb") and getattr(args, "adb") != ADB:
        raise RollbackRecoveryError("torn rollback accepts only the fixed adb executable")
    if hasattr(args, "output_root"):
        raise RollbackRecoveryError(
            "output_root selector is disabled; torn rollback evidence is fixed under REPO_ROOT"
        )
    root = Path(REPO_ROOT)
    _reject_symlink_components(root, "output")
    root = root.resolve(strict=False)
    journal_path, manifest_path = _output_paths(root, experiment_id)
    source_path = _source_path(root, args)
    source, source_raw, source_sha256 = _stable_source(source_path)
    source_evidence = _validate_source(source, source_path=source_path)
    source_semantic_sha256 = str(source_evidence["semantic_sha256"])
    source_profile = str(source_evidence["profile"])
    validated_source_identity = _stable_source_identity(
        source_path,
        expected_sha256=source_sha256,
        expected_size=len(source_raw),
    )
    # The source-consumption claim is anchored to the fixed repository root,
    # never to the caller-selected evidence root.  Check it before any
    # target/device contact so a second experiment/path/root gets a zero
    # transport refusal for the same validated semantic profile/path key,
    # even if the canonical source JSON was reformatted or had ignored extras
    # added between attempts.
    source_claim_path = _source_claim_path(source_semantic_sha256)
    _require_source_claim_available(source_claim_path)
    image_size, image_hash = _stable_image_digest(ROLLBACK_IMAGE)
    if image_size != BOOT_PREFIX_SIZE or image_hash != ROLLBACK_SHA256:
        raise RollbackRecoveryError("pinned rollback image does not match fixed hash/size")

    started = utc_now()
    target: dict[str, object] | None = None
    endpoint: AdbEndpoint | None = None
    target_verified = False
    current_pre_hash: str | None = None
    current_pre_size: int | None = None
    write_count = 0
    effect_started = False
    staged = False
    pre_effect_rebind_failed = False
    cleanup_proved = False
    cleanup_error: str | None = None
    source_claim_data: bytes | None = None
    source_claimed = False
    source_claim_attempted = False
    effect_identity: dict[str, object] | None = None
    effect_key_sha256: str | None = None
    effect_claim_path: Path | None = None
    effect_claim_data: bytes | None = None
    effect_claimed = False
    effect_claim_attempted = False
    preimage_evidence: dict[str, object] | None = None
    journal: dict[str, object] = {
        "schema": JOURNAL_SCHEMA,
        "experiment_id": experiment_id,
        "started_utc": started,
        "status": "INTENT_DURABLE_PRE_EFFECT",
        "source_flash_journal_path": str(source_path),
        "source_flash_journal_sha256": source_sha256,
        "source_flash_journal_size": len(source_raw),
        "source_flash_journal_identity": validated_source_identity,
        "source_semantic_sha256": source_semantic_sha256,
        "source_consumption_claim_key_sha256": source_semantic_sha256,
        "source_semantic_identity": source_evidence["semantic_identity"],
        "source_profile": source_profile,
        "source_consumption_claim_path": str(source_claim_path),
        "source_consumption_claimed": False,
        "source_consumption_claim_attempted": False,
        "source_consumption_claim_sha256": None,
        "source_consumption_claim_size": None,
        "source_consumption_claim_phase": None,
        "source_evidence": source_evidence,
        "expected_target": _expected_target(),
        "target_verified": False,
        "target": None,
        "rollback_image_path": str(ROLLBACK_IMAGE),
        "rollback_image_sha256": image_hash,
        "rollback_image_size": image_size,
        "boot_alias": BOOT_BLOCK_ALIAS,
        "boot_node": BOOT_BLOCK_RESOLVED,
        "remote_staging": None,
        "preimage_evidence": None,
        "physical_effect_claim": {
            "claimed": False,
            "attempted": False,
            "key_sha256": None,
            "claim_path": None,
            "claim_sha256": None,
            "claim_size": None,
        },
        "cleanup_intent": None,
        "cleanup_intent_result": None,
        "pre_staging_removed": False,
        "pre_cleanup_error": None,
        "effect_replayed": False,
        "effect_ambiguous": False,
        "automatic_retries": False,
        "reboot_dispatched": False,
        "effect_armed": False,
        "effect_dispatched": False,
        "write_count": 0,
        "staging_attempted": False,
        "staging_status": None,
        "partition_writes": False,
        "cleanup_proved": False,
        "cleanup_error": None,
        "reconcile_required": False,
    }
    journal_data = _create_initial_json(journal_path, journal)

    def persist() -> None:
        nonlocal journal_data
        journal_data = _atomic_json(journal_path, journal)

    def publish_failure(status: str, error: BaseException) -> None:
        journal["status"] = status
        journal["error"] = f"{type(error).__name__}: {error}"
        journal["completed_utc"] = utc_now()
        persist()
        _publish(
            manifest_path,
            experiment_id=experiment_id,
            started=started,
            status=status,
            target=target,
            target_verified=target_verified,
            source_sha256=source_sha256,
            source_size=len(source_raw),
            source_semantic_sha256=source_semantic_sha256,
            source_profile=source_profile,
            journal_data=journal_data,
            current_pre_hash=current_pre_hash,
            current_pre_size=current_pre_size,
            write_count=write_count,
            cleanup_proved=cleanup_proved,
            error=f"{type(error).__name__}: {error}",
            source_claim_data=source_claim_data,
            source_claim_attempted=source_claim_attempted,
            source_claimed=source_claimed,
            preimage_evidence=preimage_evidence,
            effect_claim_key_sha256=effect_key_sha256,
            effect_claim_data=effect_claim_data,
            effect_claim_attempted=effect_claim_attempted,
            effect_claimed=effect_claimed,
        )

    def consume_source_claim(terminal: str, *, claim_phase: str | None = None) -> None:
        """Acquire and verify the one-way source lease at its safe boundary."""

        nonlocal source_claim_data, source_claimed, source_claim_attempted
        if source_claimed or source_claim_attempted:
            raise RollbackRecoveryError("source journal consumption was already attempted")
        # This repeat validation is host-only and immediately precedes the
        # O_EXCL claim.  A path/hash/identity change therefore cannot redirect
        # the claim to a different source journal.
        claim_identity = _stable_source_identity(
            source_path,
            expected_sha256=source_sha256,
            expected_size=len(source_raw),
            expected_identity=validated_source_identity,
        )
        source_claim_attempted = True
        journal["source_consumption_claim_attempted"] = True
        try:
            source_claim_data = _create_source_claim(
                source_claim_path,
                source_path=source_path,
                source_sha256=source_sha256,
                source_semantic_sha256=str(source_evidence["semantic_sha256"]),
                source_semantic_identity=source_evidence["semantic_identity"],
                source_size=len(source_raw),
                source_identity=claim_identity,
                source_profile=str(source_evidence["profile"]),
                experiment_id=experiment_id,
                terminal=terminal,
                claim_phase=claim_phase,
            )
            _verify_source_claim(source_claim_path, source_claim_data)
        except BaseException:
            # O_EXCL creation is intentionally not rolled back.  A failure
            # after the inode exists is itself a no-replay lock/crash record.
            source_claimed = source_claim_path.exists() or source_claim_path.is_symlink()
            journal["source_consumption_claimed"] = source_claimed
            raise
        source_claimed = True
        journal["source_consumption_claimed"] = True
        journal["source_consumption_claim_sha256"] = sha256(source_claim_data)
        journal["source_consumption_claim_size"] = len(source_claim_data)
        journal["source_consumption_claim_terminal"] = terminal
        journal["source_consumption_claim_phase"] = claim_phase or terminal

    def consume_effect_claim(terminal: str) -> None:
        """Reserve the physical rollback key independently of source/ID."""

        nonlocal effect_claim_data, effect_claimed, effect_claim_attempted
        if effect_identity is None or effect_key_sha256 is None or effect_claim_path is None:
            raise RollbackRecoveryError("rollback physical effect claim identity is missing")
        if effect_claimed or effect_claim_attempted:
            raise RollbackRecoveryError("rollback physical effect claim was already attempted")
        effect_claim_attempted = True
        physical = journal.get("physical_effect_claim")
        if isinstance(physical, dict):
            physical["attempted"] = True

        # A normal remapper owner may already have reserved this exact
        # preimage key before its guarded write became ambiguous.  Recovery is
        # allowed to continue through that claim only for the same canonical
        # source journal and only at a pre-effect or terminal zero-write
        # boundary.  Every other
        # complete owner, and every partial final inode, is an irreversible
        # collision: do not stage, cleanup, or attempt another write.
        try:
            existing = inspect_boot_prefix_claim(
                Path(REPO_ROOT),
                current_pre_hash,
                current_pre_size,
            )
        except PhysicalClaimPartial as exc:
            raise RollbackRecoveryError(str(exc)) from exc
        if existing is not None:
            if terminal not in {
                "before_recovery_effect_marker",
                "before_zero_write_cleanup",
                "terminal_zero_write_close",
            }:
                raise RollbackRecoveryError(
                    "rollback physical effect claim already exists; replay forbidden"
                )
            # Re-check the independent source-consumption claim at the
            # continuation boundary.  A source claim acquired by another
            # recovery owner makes continuation unsafe even if the normal
            # physical claim itself is a valid ambiguous owner.
            _require_source_claim_available(source_claim_path)
            try:
                validate_normal_remapper_continuation(
                    existing,
                    root=Path(REPO_ROOT),
                    journal_path=source_path,
                    profile=source_profile,
                    predecessor_sha256=str(source_evidence["predecessor_sha256"]),
                    predecessor_size=int(source_evidence["predecessor_size"]),
                )
            except (PhysicalClaimError, ValueError, TypeError) as exc:
                raise RollbackRecoveryError(
                    "rollback physical effect claim belongs to a different owner/source"
                ) from exc
            effect_claim_data = existing.data
            effect_claimed = True
            if isinstance(physical, dict):
                physical.update(
                    {
                        "claimed": True,
                        "claim_sha256": sha256(effect_claim_data),
                        "claim_size": len(effect_claim_data),
                        "continued_from_normal_ambiguous": True,
                        "terminal": terminal,
                    }
                )
            return
        try:
            effect_claim_data = _create_rollback_effect_claim(
                effect_claim_path,
                identity=effect_identity,
                effect_key_sha256=effect_key_sha256,
                experiment_id=experiment_id,
                terminal=terminal,
            )
        except BaseException:
            effect_claimed = effect_claim_path.exists() or effect_claim_path.is_symlink()
            if isinstance(physical, dict):
                physical["claimed"] = effect_claimed
            raise
        effect_claimed = True
        if isinstance(physical, dict):
            physical.update(
                {
                    "claimed": True,
                    "claim_sha256": sha256(effect_claim_data),
                    "claim_size": len(effect_claim_data),
                    "terminal": terminal,
                }
            )

    try:
        # Initial exact target bind is read-only.  Every later stateful
        # mutation gets a fresh exact revalidation immediately beforehand.
        endpoint = _revalidate_recovery()
        target = {
            "state": endpoint.state,
            "model": TARGET_MODEL,
            "device": TARGET_DEVICE,
            "twrp_version": TWRP_VERSION,
            "serial": endpoint.serial,
            "serial_sha256": endpoint.serial_sha256,
        }
        target_verified = True
        journal["target"] = {key: value for key, value in target.items() if key != "serial"}
        journal["target_verified"] = True
        persist()

        current_pre_hash = _boot_hash(endpoint.serial)
        current_pre_size = _boot_size(endpoint.serial)
        if current_pre_size != BOOT_PREFIX_SIZE:
            raise RollbackRecoveryError("current boot prefix is not complete")
        journal.update(
            {
                "current_pre_hash_sha256": current_pre_hash,
                "current_pre_hash_size": current_pre_size,
            }
        )
        persist()
        # A complete known V024 prefix is only eligible when it belongs to
        # this source journal's causal edge.  Unknown/torn bytes remain
        # eligible for staging, while a known impossible state refuses before
        # any staging attempt or source-consumption claim.
        _validate_current_source_state(
            current_pre_hash,
            current_pre_size,
            source_evidence,
        )

        # Unknown bytes are eligible only after a bounded binary capture has
        # proved a stable device-before/host/device-after hash triple and an
        # exact per-block mixture of the source predecessor/intended V024
        # artifacts.  This all happens before the physical effect claim, so
        # an unrelated/custom image cannot consume either claim or stage.
        if current_pre_hash not in KNOWN_V024_BOOT_HASHES:
            preimage_evidence = _capture_unknown_preimage(
                root,
                experiment_id,
                endpoint.serial,
                current_pre_hash,
                current_pre_size,
                source_evidence,
            )
            journal["preimage_evidence"] = preimage_evidence
            persist()

        effect_identity, effect_key_sha256 = _rollback_effect_identity(
            current_pre_hash,
            current_pre_size,
        )
        effect_claim_path = _rollback_effect_claim_path(effect_key_sha256)
        remote_staging = _rollback_staging_for_effect(
            source_semantic_sha256,
            effect_key_sha256,
        )
        journal["physical_effect_claim"].update(
            {
                "key_sha256": effect_key_sha256,
                "claim_path": str(effect_claim_path),
            }
        )
        journal["remote_staging"] = remote_staging
        if current_pre_hash != ROLLBACK_SHA256:
            # A physical-key collision is checked/acquired before cleanup or
            # push.  The losing source therefore cannot overwrite the winner's
            # staging bytes, even when its profile and experiment differ.
            consume_effect_claim("before_recovery_effect_marker")
            journal["physical_effect_claim"].update(
                {
                    "key_sha256": effect_key_sha256,
                    "claim_path": str(effect_claim_path),
                    "claimed": effect_claimed,
                    "attempted": effect_claim_attempted,
                    "claim_sha256": sha256(effect_claim_data) if effect_claim_data else None,
                    "claim_size": len(effect_claim_data) if effect_claim_data else None,
                }
            )
            persist()
        else:
            # Exact rollback is a zero-write terminal, but its cleanup still
            # mutates the device-side staging namespace.  Reserve both the
            # shared physical preimage key and the source-specific lease
            # before that first cleanup rebind/rm.  The source claim keeps its
            # finalizer-compatible terminal value while the separate phase
            # field proves this earlier pre-cleanup acquisition.
            consume_effect_claim("before_zero_write_cleanup")
            journal["physical_effect_claim"].update(
                {
                    "key_sha256": effect_key_sha256,
                    "claim_path": str(effect_claim_path),
                    "claimed": effect_claimed,
                    "attempted": effect_claim_attempted,
                    "claim_sha256": sha256(effect_claim_data) if effect_claim_data else None,
                    "claim_size": len(effect_claim_data) if effect_claim_data else None,
                }
            )
            persist()
            consume_source_claim(
                "terminal_zero_write_close",
                claim_phase="before_staging_cleanup",
            )
            persist()
            journal["source_consumption_claim_phase"] = "before_staging_cleanup"
            journal["status"] = ALREADY_STATUS
            persist()

        if current_pre_hash == ROLLBACK_SHA256:
            # This is the idempotent no-write close.  There is no staging push
            # and no effect marker when the exact rollback is already present.
            # Both claims were acquired above, before entering terminal
            # cleanup; the source lease still records the explicit
            # terminal_zero_write_close classification.  No marker or
            # partition write is published on this path.
            pass
        else:
            # All pre-staging safety gates have passed: exact source/profile
            # validation, target/current-state validation, optional unknown
            # mixture proof, and the shared physical claim.  Consume the
            # source-specific O_EXCL lease now, immediately before the first
            # staging cleanup.  A competing continuation therefore fails here
            # and cannot issue rm/push/hash/dd against this source's staging
            # transaction.  Any failure after this durable lease is
            # reconciliation-only and is never an automatic replay.
            # Keep the legacy terminal classification for the finalizer while
            # recording the stronger acquisition ordering separately.
            consume_source_claim(
                "before_recovery_effect_marker",
                claim_phase="before_staging_cleanup",
            )
            persist()
            # Publish cleanup intent before obtaining the authority used for
            # the cleanup mutation.  The rebind and the remove/absence proof
            # then occur contiguously, with no fsync between the final bind
            # and ``rm``.
            journal["cleanup_intent"] = {
                "phase": "pre_staging",
                "status": "CLEANUP_INTENT_DURABLE",
                "remote_staging": remote_staging,
            }
            persist()
            endpoint = _revalidate_recovery(endpoint)
            pre_cleanup_ok, pre_cleanup_error = _cleanup_remote(
                endpoint.serial,
                remote_staging,
            )
            journal.update(
                {
                    "pre_staging_removed": pre_cleanup_ok,
                    "pre_cleanup_error": pre_cleanup_error,
                    "pre_cleanup_target_serial_sha256": endpoint.serial_sha256,
                    "pre_cleanup_revalidated": True,
                    "cleanup_intent_result": "PROVED" if pre_cleanup_ok else "FAILED",
                }
            )
            persist()
            if not pre_cleanup_ok:
                journal["staging_cleanup_deferred"] = True
                journal["reconcile_required"] = True
                raise RollbackRecoveryError(
                    f"stale rollback staging could not be removed: {pre_cleanup_error}"
                )
            # Mark staging as attempted before the push so a transport error
            # can still receive one fresh-bind cleanup before any effect.
            staged = True
            journal["staging_attempted"] = True
            journal["staging_status"] = "STAGING_PUSH_STARTED"
            persist()
            # The staging-attempt marker is durable.  Rebind immediately
            # afterward and issue the push without another journal fsync or
            # device command in between.
            endpoint = _revalidate_recovery(endpoint)
            journal["staging_rebind_after_attempt"] = True
            journal["staging_rebind_target_serial_sha256"] = endpoint.serial_sha256
            run_checked((ADB, "-s", endpoint.serial, "push", str(ROLLBACK_IMAGE), remote_staging))
            journal["pre_push_revalidated"] = True
            journal["pre_push_target_serial_sha256"] = endpoint.serial_sha256
            journal["staging_status"] = "STAGING_PUSH_RETURNED"
            persist()
            remote_hash = _remote_hash(endpoint.serial, remote_staging)
            remote_size = _remote_size(endpoint.serial, remote_staging)
            journal.update(
                {
                    "remote_staging_sha256": remote_hash,
                    "remote_staging_size": remote_size,
                }
            )
            persist()
            if remote_hash != ROLLBACK_SHA256 or remote_size != BOOT_PREFIX_SIZE:
                raise RollbackRecoveryError("rollback staging hash/size mismatch")

            try:
                endpoint = _revalidate_recovery(endpoint)
            except BaseException:
                pre_effect_rebind_failed = True
                raise
            post_staging_hash = _boot_hash(endpoint.serial)
            post_staging_size = _boot_size(endpoint.serial)
            journal.update(
                {
                    "post_staging_predecessor_sha256": post_staging_hash,
                    "post_staging_predecessor_size": post_staging_size,
                    "post_staging_predecessor_revalidated": True,
                    "pre_effect_revalidated": True,
                    "pre_effect_target_serial_sha256": endpoint.serial_sha256,
                }
            )
            persist()
            if (
                post_staging_hash != current_pre_hash
                or post_staging_size != current_pre_size
            ):
                raise RollbackRecoveryError(
                    "rollback predecessor changed after staging: "
                    f"before={current_pre_hash}/{current_pre_size} "
                    f"after={post_staging_hash}/{post_staging_size}"
                )
            journal.update(
                {
                    "status": EFFECT_STARTED_STATUS,
                    "effect_armed": True,
                    "effect_dispatched": True,
                    "write_count": 1,
                    "partition_writes": True,
                    "effect_argv": [
                        "dd",
                        f"if={remote_staging}",
                        f"of={BOOT_BLOCK_RESOLVED}",
                        f"bs={DD_BLOCK_SIZE}",
                        f"count={DD_BLOCK_COUNT}",
                        "conv=fsync",
                    ],
                }
            )
            write_count = 1
            effect_started = True
            persist()
            # The marker is durable, so every subsequent device command is
            # reconciliation-sensitive.  Freshly rebind, rehash the fixed
            # staging object, then perform one final exact rebind immediately
            # before the sole rollback write.  There is deliberately no host
            # fsync or device command between that final rebind and ``dd``.
            endpoint = _revalidate_recovery(endpoint)
            journal["post_marker_revalidated"] = True
            journal["post_marker_target_serial_sha256"] = endpoint.serial_sha256
            # The rebind above is immediately followed by one guarded shell
            # transaction.  It rechecks the current predecessor and staging
            # bytes in the same remote command and executes exactly one dd
            # only when both hashes/sizes match.
            guarded_command = _guarded_rollback_command(
                remote_staging,
                current_pre_hash,
                ROLLBACK_SHA256,
                current_pre_size,
            )
            write_output = _adb_shell(endpoint.serial, guarded_command)
            guarded_receipt = _parse_guarded_rollback_receipt(
                write_output,
                expected_predecessor_sha256=current_pre_hash,
                expected_staging_sha256=ROLLBACK_SHA256,
                expected_predecessor_size=current_pre_size,
            )
            journal["guarded_effect_command"] = guarded_command
            journal["guarded_effect_receipt"] = guarded_receipt
            journal["status"] = "EFFECT_RETURNED_VERIFYING_READBACK"
            journal["write_output_tail"] = write_output[-512:]
            persist()
            readback_hash = _boot_hash(endpoint.serial)
            readback_size = _boot_size(endpoint.serial)
            journal.update(
                {
                    "readback_sha256": readback_hash,
                    "readback_size": readback_size,
                }
            )
            persist()
            if readback_hash != ROLLBACK_SHA256 or readback_size != BOOT_PREFIX_SIZE:
                raise RollbackRecoveryError("rollback readback hash/size mismatch")
            journal["status"] = READBACK_STATUS
            persist()

        # A cleanup mutation also receives a fresh exact binding.  This is
        # required for both the already-rollback idempotent path and a
        # verified one-write path.
        if journal.get("status") in {ALREADY_STATUS, READBACK_STATUS}:
            journal["cleanup_intent"] = {
                "phase": "terminal_staging_cleanup",
                "status": "CLEANUP_INTENT_DURABLE",
                "remote_staging": remote_staging,
            }
            # The intent is durable before the authority rebind.  The rebind
            # and cleanup then run contiguously; no fsync is inserted between
            # the final bind and the first cleanup mutation.
            persist()
            try:
                endpoint = _revalidate_recovery(endpoint)
            except BaseException as cleanup_exc:
                journal["status"] = "CLEANUP_REBIND_FAILED_RECONCILIATION_REQUIRED"
                journal["staging_cleanup_deferred"] = True
                journal["reconcile_required"] = True
                journal["cleanup_error"] = (
                    f"final cleanup Recovery rebind failed: {type(cleanup_exc).__name__}: "
                    f"{cleanup_exc}"
                )
                persist()
                raise RollbackRecoveryError(str(cleanup_exc)) from cleanup_exc
            cleanup_proved, cleanup_error = _cleanup_remote(
                endpoint.serial,
                remote_staging,
            )
            journal.update(
                {
                    "final_cleanup_revalidated": True,
                    "final_cleanup_target_serial_sha256": endpoint.serial_sha256,
                    "cleanup_proved": cleanup_proved,
                    "cleanup_error": cleanup_error,
                    "cleanup_intent_result": "PROVED" if cleanup_proved else "FAILED",
                }
            )
            # Binding and result are recorded only after the cleanup returns.
            persist()
            if not cleanup_proved:
                journal["status"] = "CLEANUP_FAILED_RECONCILIATION_REQUIRED"
                journal["reconcile_required"] = True
                persist()
                raise RollbackRecoveryError(
                    f"rollback staging cleanup was not proved: {cleanup_error}"
                )
            journal["status"] = (
                PASS_ALREADY_STATUS if journal["status"] == ALREADY_STATUS else PASS_STATUS
            )
            journal["completed_utc"] = utc_now()
            persist()
            _publish(
                manifest_path,
                experiment_id=experiment_id,
                started=started,
                status=str(journal["status"]),
                target=target,
                target_verified=target_verified,
                source_sha256=source_sha256,
                source_size=len(source_raw),
                source_semantic_sha256=source_semantic_sha256,
                source_profile=source_profile,
                journal_data=journal_data,
                current_pre_hash=current_pre_hash,
                current_pre_size=current_pre_size,
                write_count=write_count,
                cleanup_proved=cleanup_proved,
                error=None,
                source_claim_data=source_claim_data,
                source_claim_attempted=source_claim_attempted,
                source_claimed=source_claimed,
                preimage_evidence=preimage_evidence,
                effect_claim_key_sha256=effect_key_sha256,
                effect_claim_data=effect_claim_data,
                effect_claim_attempted=effect_claim_attempted,
                effect_claimed=effect_claimed,
            )
            return journal_path, manifest_path
    except BaseException as exc:
        current_status = str(journal.get("status"))
        source_claim_boundary = source_claimed or source_claim_attempted
        effect_claim_boundary = effect_claimed or effect_claim_attempted
        claim_boundary = source_claim_boundary or effect_claim_boundary
        if claim_boundary and not effect_started and current_status not in {
            "CLEANUP_REBIND_FAILED_RECONCILIATION_REQUIRED",
            "CLEANUP_FAILED_RECONCILIATION_REQUIRED",
        }:
            # A claim is irreversible even when a host fsync/marker update
            # crashes immediately afterwards.  Do not clean staging or allow
            # a later invocation to reinterpret this source as unconsumed.
            journal["status"] = (
                SOURCE_CLAIMED_STATUS
                if source_claim_boundary
                else EFFECT_CLAIMED_STATUS
            )
            journal["source_consumption_claimed"] = bool(source_claimed)
            journal["source_consumption_claim_attempted"] = source_claim_attempted
            physical = journal.get("physical_effect_claim")
            if isinstance(physical, dict):
                physical["claimed"] = bool(effect_claimed)
                physical["attempted"] = effect_claim_attempted
            journal["staging_cleanup_deferred"] = True
            journal["reconcile_required"] = True
            journal["cleanup_error"] = (
                "deferred after irreversible claim; reconciliation required"
            )
        elif effect_started and current_status not in {
            "CLEANUP_REBIND_FAILED_RECONCILIATION_REQUIRED",
            "CLEANUP_FAILED_RECONCILIATION_REQUIRED",
        }:
            # After the durable marker no cleanup or replay is safe unless the
            # complete rollback readback already proved.  Preserve write_count=1.
            journal["status"] = AMBIGUOUS_STATUS
            journal["effect_armed"] = True
            journal["effect_dispatched"] = True
            journal["effect_ambiguous"] = True
            journal["automatic_retries"] = False
            journal["reboot_dispatched"] = False
            journal["write_count"] = 1
            journal["partition_writes"] = True
            journal["staging_cleanup_deferred"] = True
            journal["reconcile_required"] = True
            journal["cleanup_error"] = "deferred after effect marker; reconciliation required"
        elif current_status not in {
            "CLEANUP_REBIND_FAILED_RECONCILIATION_REQUIRED",
            "CLEANUP_FAILED_RECONCILIATION_REQUIRED",
        }:
            journal["status"] = REFUSED_STATUS
            if not claim_boundary and not effect_started:
                # The marker was never durably published.  The in-memory
                # effect fields were prepared for that publication, so clear
                # them before recording the genuine zero-effect refusal.
                journal["effect_armed"] = False
                journal["effect_dispatched"] = False
                journal["write_count"] = 0
                journal["partition_writes"] = False
                write_count = 0
            if staged:
                # A failed stage may have left a remote object, but no boot
                # effect was armed.  Cleanup is attempted only after a fresh
                # exact Recovery bind; a rebind failure emits zero cleanup
                # commands and remains pre-effect reconciliation evidence.
                if pre_effect_rebind_failed:
                    cleanup_proved = False
                    cleanup_error = "pre-effect cleanup deferred after Recovery rebind failure"
                    journal["staging_cleanup_deferred"] = True
                    journal["reconcile_required"] = True
                    journal["cleanup_error"] = cleanup_error
                try:
                    if endpoint is not None and not pre_effect_rebind_failed:
                        journal["cleanup_intent"] = {
                            "phase": "pre_effect_failure_staging_cleanup",
                            "status": "CLEANUP_INTENT_DURABLE",
                            "remote_staging": remote_staging,
                        }
                        persist()
                        endpoint = _revalidate_recovery(endpoint)
                        cleanup_proved, cleanup_error = _cleanup_remote(
                            endpoint.serial,
                            remote_staging,
                        )
                        journal.update(
                            {
                                "pre_effect_cleanup_revalidated": True,
                                "pre_effect_cleanup_target_serial_sha256": endpoint.serial_sha256,
                                "cleanup_proved": cleanup_proved,
                                "cleanup_error": cleanup_error,
                                "cleanup_intent_result": (
                                    "PROVED" if cleanup_proved else "FAILED"
                                ),
                            }
                        )
                        persist()
                        if not cleanup_proved:
                            journal["staging_cleanup_deferred"] = True
                            journal["reconcile_required"] = True
                except BaseException as cleanup_exc:
                    cleanup_proved = False
                    cleanup_error = (
                        f"pre-effect cleanup rebind failed: {type(cleanup_exc).__name__}: "
                        f"{cleanup_exc}"
                    )
                    journal["staging_cleanup_deferred"] = True
                    journal["reconcile_required"] = True
                    journal["cleanup_error"] = cleanup_error
        publish_failure(str(journal["status"]), exc)
        raise RollbackRecoveryError(
            f"torn-write rollback failed; evidence requires reconciliation: {exc}"
        ) from exc

    raise RollbackRecoveryError("torn-write rollback did not reach a terminal state")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument(
        "--flash-journal",
        "--journal",
        "--source-journal",
        "--referenced-journal",
        dest="flash_journal",
        type=Path,
        required=True,
        help="stable referenced ambiguous V024 flash journal",
    )
    parser.add_argument("--execute", action="store_true")
    return parser


def make_parser() -> argparse.ArgumentParser:
    return build_parser()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    journal, manifest = collect(args)
    print(f"journal: {journal}")
    print(f"public manifest: {manifest}")
    return 0


# Descriptive alias used by callers that treat this owner as a recovery
# operation rather than a collector; it retains the same fixed CLI contract.
recover = collect


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ADB",
    "ALREADY_STATUS",
    "BOOT_BLOCK_ALIAS",
    "BOOT_BLOCK_RESOLVED",
    "BOOT_PREFIX_SIZE",
    "CONTROL_SHA256",
    "DD_BLOCK_COUNT",
    "DD_BLOCK_SIZE",
    "JOURNAL_SCHEMA",
    "KNOWN_V024_BOOT_HASHES",
    "PASS_ALREADY_STATUS",
    "PASS_STATUS",
    "PUBLIC_SCHEMA",
    "READ_SHA256",
    "REFUSED_STATUS",
    "REMOTE_STAGING",
    "ROLLBACK_IMAGE",
    "ROLLBACK_HASH",
    "ROLLBACK_SHA256",
    "ROLLBACK_SIZE",
    "RollbackRecoveryError",
    "SOURCE_AMBIGUOUS_STATUS",
    "SOURCE_CLAIM_SCHEMA",
    "SOURCE_CLAIM_PREFIX",
    "SOURCE_CLAIMED_STATUS",
    "SOURCE_SCHEMA",
    "TARGET_DEVICE",
    "TARGET_MODEL",
    "TARGET_SERIAL_SHA256",
    "TWRP_VERSION",
    "V024_ALLOWED_PREDECESSORS",
    "V024_PROFILE_HASHES",
    "build_parser",
    "collect",
    "recover",
    "main",
    "make_parser",
    "run_checked",
    "sha256",
]
