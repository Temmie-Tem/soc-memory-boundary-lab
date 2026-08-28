#!/usr/bin/env python3
"""Host-only physical-effect claims shared by the V024 boot owners.

The claim files in this module are deliberately independent of experiment IDs
and requested profiles.  Their final path is created with ``O_EXCL`` and
``O_NOFOLLOW`` and the file and containing directory are fsynced before the
caller is allowed to issue an effect.  A partial or malformed final inode is
an irreversible reconciliation condition, never an invitation to replace it.

This module imports no device, ADB, socket, or bridge code.  Callers provide
only a fixed repository root and provenance metadata for the private claim
contents; provenance is never included in either physical claim key.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping


BOOT_PREFIX_CLAIM_SCHEMA = "sdm855-a90-v024-boot-prefix-physical-claim-v1"
BOOT_PREFIX_CLAIM_PREFIX = "verification-024-boot-prefix-physical-"
BOOT_PREFIX_PARTITION = "/dev/block/sda24"
BOOT_PREFIX_SIZE = 60_882_944
BOOT_PREFIX_BLOCK_SIZE = 4096
BOOT_PREFIX_BLOCK_COUNT = BOOT_PREFIX_SIZE // BOOT_PREFIX_BLOCK_SIZE

NATIVE_TRANSITION_CLAIM_SCHEMA = "sdm855-a90-v024-native-boot-transition-claim-v1"
NATIVE_TRANSITION_CLAIM_PREFIX = "verification-024-native-boot-transition-"
NATIVE_TRANSITION_RESOURCE = "a90-native-boot-transition"

# The continuation validator is intentionally self-contained.  Keeping the
# producer matrix here means a forged/rewritten ambiguous journal cannot make
# a complete normal-owner claim look like a causally valid recovery source.
V024_IMAGE_HASHES = {
    "control": "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247",
    "read": "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed",
    "rollback": "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb",
}
V024_PREDECESSORS = {
    "control": [V024_IMAGE_HASHES["rollback"]],
    "read": [V024_IMAGE_HASHES["control"]],
    # Match the normal remapper producer's ``sorted(allowed)`` serialization.
    "rollback": [V024_IMAGE_HASHES["read"], V024_IMAGE_HASHES["control"]],
}
V024_STAGING = {
    "control": "/tmp/sdm855-remapper-boot.img",
    "read": "/tmp/sdm855-remapper-boot-read.img",
    "rollback": "/tmp/sdm855-remapper-boot-rollback.img",
}

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
MAX_CLAIM_BYTES = 1024 * 1024


class PhysicalClaimError(RuntimeError):
    """A claim is invalid, partial, or cannot be acquired safely."""


class PhysicalClaimAlreadyExists(PhysicalClaimError):
    """A complete claim already owns this physical effect key."""

    def __init__(self, message: str, claim: "ClaimRecord | None" = None) -> None:
        super().__init__(message)
        self.claim = claim


class PhysicalClaimPartial(PhysicalClaimError):
    """A final claim inode or lock residue is incomplete and immutable."""


class ClaimRecord:
    """Validated claim data and its canonical physical identity."""

    __slots__ = ("kind", "path", "key_sha256", "identity", "record", "data")

    def __init__(
        self,
        *,
        kind: str,
        path: Path,
        key_sha256: str,
        identity: Mapping[str, object],
        record: Mapping[str, object],
        data: bytes,
    ) -> None:
        self.kind = kind
        self.path = path
        self.key_sha256 = key_sha256
        self.identity = dict(identity)
        self.record = dict(record)
        self.data = data

    def __repr__(self) -> str:
        return f"ClaimRecord(kind={self.kind!r}, key_sha256={self.key_sha256!r})"


def _json_bytes(value: object) -> bytes:
    # Match the repository's durable JSON encoding so both owners derive the
    # same key bytes without importing any transport-capable module.
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _reject_symlink_components(path: Path, label: str) -> None:
    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical
    anchor = Path(lexical.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise PhysicalClaimError(f"{label} component must not be a symlink: {cursor}")
        if cursor == anchor:
            return
        cursor = cursor.parent


def _claim_dir(root: Path) -> Path:
    root = Path(root)
    _reject_symlink_components(root, "claim root")
    resolved = root.resolve(strict=False)
    claim_dir = resolved / "evidence" / "private"
    _reject_symlink_components(claim_dir, "claim directory")
    claim_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(claim_dir, 0o700)
    return claim_dir


def _validate_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise PhysicalClaimError(f"{label} is not an exact SHA-256")
    return value


def _validate_size(value: object, label: str) -> int:
    if type(value) is not int or value != BOOT_PREFIX_SIZE:
        raise PhysicalClaimError(f"{label} is not the fixed complete boot-prefix size")
    return value


def _strict_json_object(data: bytes, label: str) -> Mapping[str, object]:
    """Decode one bounded JSON object without duplicate/NaN ambiguity."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise PhysicalClaimPartial(f"{label} contains duplicate key: {name}")
            result[name] = value
        return result

    def reject_nonfinite(value: str) -> object:
        raise PhysicalClaimPartial(f"{label} contains non-finite JSON value: {value}")

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_nonfinite,
        )
    except PhysicalClaimPartial:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PhysicalClaimPartial(f"{label} is partial or malformed") from exc
    if not isinstance(value, dict):
        raise PhysicalClaimPartial(f"{label} root is not an object")
    return value


def boot_prefix_claim_identity(
    current_preimage_sha256: str,
    current_preimage_size: int = BOOT_PREFIX_SIZE,
) -> tuple[dict[str, object], str]:
    """Return the shared normal/recovery boot-prefix identity and key.

    Only the exact current preimage, partition, and fixed geometry influence
    the key.  Requested target/profile/source/experiment provenance is kept
    out of this function by construction.
    """

    current_preimage_sha256 = _validate_hash(
        current_preimage_sha256, "boot-prefix preimage"
    )
    _validate_size(current_preimage_size, "boot-prefix preimage size")
    identity: dict[str, object] = {
        "schema": BOOT_PREFIX_CLAIM_SCHEMA,
        "current_preimage_sha256": current_preimage_sha256,
        "current_preimage_size": BOOT_PREFIX_SIZE,
        "partition": BOOT_PREFIX_PARTITION,
        "block_size": BOOT_PREFIX_BLOCK_SIZE,
        "block_count": BOOT_PREFIX_BLOCK_COUNT,
    }
    return identity, sha256(_json_bytes(identity))


def native_transition_claim_identity(boot_id: str) -> tuple[dict[str, object], str]:
    """Return the shared native Recovery/reboot identity and key."""

    if not isinstance(boot_id, str) or BOOT_ID_RE.fullmatch(boot_id) is None:
        raise PhysicalClaimError("native boot_id is not an exact UUID")
    identity: dict[str, object] = {
        "schema": NATIVE_TRANSITION_CLAIM_SCHEMA,
        "resource": NATIVE_TRANSITION_RESOURCE,
        "current_native_boot_id": boot_id,
    }
    return identity, sha256(_json_bytes(identity))


def boot_prefix_claim_path(root: Path, key_sha256: str) -> Path:
    _validate_hash(key_sha256, "boot-prefix claim key")
    return _claim_dir(Path(root)) / f"{BOOT_PREFIX_CLAIM_PREFIX}{key_sha256}.claim.json"


def native_transition_claim_path(root: Path, key_sha256: str) -> Path:
    _validate_hash(key_sha256, "native transition claim key")
    return _claim_dir(Path(root)) / (
        f"{NATIVE_TRANSITION_CLAIM_PREFIX}{key_sha256}.claim.json"
    )


def _residue_paths(path: Path) -> tuple[Path, Path]:
    return (
        path.with_name(path.name + ".tmp"),
        path.with_name(path.name + ".lock"),
    )


def _require_canonical_claim_path(path: Path, *, prefix: str, key: str, label: str) -> None:
    """Reject alternate filenames/directories before any final open."""

    expected_name = f"{prefix}{key}.claim.json"
    if path.name != expected_name:
        raise PhysicalClaimError(f"{label} path is not the canonical fixed filename")
    if path.parent.name != "private" or path.parent.parent.name != "evidence":
        raise PhysicalClaimError(f"{label} path is not under fixed evidence/private")


def _raise_if_residue(path: Path, label: str) -> None:
    for residue in _residue_paths(path):
        if residue.exists() or residue.is_symlink():
            raise PhysicalClaimPartial(
                f"{label} partial lock residue exists; replay forbidden: {residue}"
            )


def _create_claim(
    path: Path,
    *,
    kind: str,
    schema: str,
    identity: Mapping[str, object],
    key_sha256: str,
    experiment_id: str,
    provenance: Mapping[str, object] | None,
) -> bytes:
    _reject_symlink_components(path.parent, f"{kind} claim")
    _raise_if_residue(path, f"{kind} claim")
    data = _json_bytes(
        {
            "schema": schema,
            "claim_key_sha256": key_sha256,
            "claim_identity": dict(identity),
            "claimed_by_experiment_id": experiment_id,
            "provenance": dict(provenance or {}),
            "effect_replayed": False,
            "claim_status": "COMPLETE",
            "created_utc": utc_now(),
        }
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise PhysicalClaimAlreadyExists(
            f"{kind} physical claim already exists; replay forbidden: {path}"
        ) from exc
    except OSError as exc:
        raise PhysicalClaimError(f"{kind} physical claim could not be acquired") from exc
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PhysicalClaimError(f"short {kind} physical claim write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
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
    except OSError as exc:
        # The final inode remains in place as a partial/reconciliation lock.
        raise PhysicalClaimPartial(
            f"{kind} physical claim directory durability failed"
        ) from exc
    return data


def create_boot_prefix_claim(
    path: Path,
    *,
    identity: Mapping[str, object],
    key_sha256: str,
    experiment_id: str,
    provenance: Mapping[str, object] | None = None,
) -> bytes:
    expected_identity, expected_key = boot_prefix_claim_identity(
        identity.get("current_preimage_sha256"),  # type: ignore[arg-type]
        identity.get("current_preimage_size", -1),  # type: ignore[arg-type]
    )
    if dict(identity) != expected_identity or key_sha256 != expected_key:
        raise PhysicalClaimError("boot-prefix claim identity/key is not canonical")
    path = Path(path)
    _require_canonical_claim_path(
        path,
        prefix=BOOT_PREFIX_CLAIM_PREFIX,
        key=expected_key,
        label="boot-prefix claim",
    )
    return _create_claim(
        path,
        kind="boot-prefix",
        schema=BOOT_PREFIX_CLAIM_SCHEMA,
        identity=expected_identity,
        key_sha256=expected_key,
        experiment_id=experiment_id,
        provenance=provenance,
    )


def create_native_transition_claim(
    path: Path,
    *,
    identity: Mapping[str, object],
    key_sha256: str,
    experiment_id: str,
    provenance: Mapping[str, object] | None = None,
) -> bytes:
    expected_identity, expected_key = native_transition_claim_identity(
        identity.get("current_native_boot_id"),  # type: ignore[arg-type]
    )
    if dict(identity) != expected_identity or key_sha256 != expected_key:
        raise PhysicalClaimError("native transition claim identity/key is not canonical")
    path = Path(path)
    _require_canonical_claim_path(
        path,
        prefix=NATIVE_TRANSITION_CLAIM_PREFIX,
        key=expected_key,
        label="native transition claim",
    )
    return _create_claim(
        path,
        kind="native-transition",
        schema=NATIVE_TRANSITION_CLAIM_SCHEMA,
        identity=expected_identity,
        key_sha256=expected_key,
        experiment_id=experiment_id,
        provenance=provenance,
    )


def _read_regular(path: Path, label: str) -> tuple[bytes, os.stat_result]:
    _reject_symlink_components(path, label)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PhysicalClaimPartial(f"{label} is unavailable or partial: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PhysicalClaimPartial(f"{label} is not a regular file")
        if before.st_size > MAX_CLAIM_BYTES:
            raise PhysicalClaimPartial(f"{label} exceeds fixed size bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CLAIM_BYTES:
                raise PhysicalClaimPartial(f"{label} exceeds fixed size bound")
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
        ) or total != before.st_size:
            raise PhysicalClaimPartial(f"{label} changed while being read")
        return b"".join(chunks), before
    except OSError as exc:
        raise PhysicalClaimPartial(f"{label} could not be read stably") from exc
    finally:
        os.close(descriptor)


def _parse_claim(data: bytes, *, kind: str, schema: str, identity: Mapping[str, object], key: str, path: Path) -> ClaimRecord:
    value = _strict_json_object(data, f"{kind} claim")
    if value.get("schema") != schema:
        raise PhysicalClaimPartial(f"{kind} claim schema is not exact")
    if value.get("claim_key_sha256") != key:
        raise PhysicalClaimPartial(f"{kind} claim key is not exact")
    claim_identity = value.get("claim_identity")
    if not isinstance(claim_identity, dict) or claim_identity != dict(identity):
        raise PhysicalClaimPartial(f"{kind} claim identity is not canonical")
    if value.get("effect_replayed") is not False:
        raise PhysicalClaimPartial(f"{kind} claim effect_replayed is not exact false")
    if value.get("claim_status") != "COMPLETE":
        raise PhysicalClaimPartial(f"{kind} claim is not complete")
    if not isinstance(value.get("claimed_by_experiment_id"), str):
        raise PhysicalClaimPartial(f"{kind} claim owner is missing")
    provenance = value.get("provenance")
    if not isinstance(provenance, dict):
        raise PhysicalClaimPartial(f"{kind} claim provenance is missing")
    return ClaimRecord(
        kind=kind,
        path=path,
        key_sha256=key,
        identity=identity,
        record=value,
        data=data,
    )


def _inspect(
    path: Path,
    *,
    kind: str,
    schema: str,
    identity: Mapping[str, object],
    key: str,
) -> ClaimRecord | None:
    _reject_symlink_components(path.parent, f"{kind} claim")
    _raise_if_residue(path, f"{kind} claim")
    if not path.exists() and not path.is_symlink():
        return None
    data, _ = _read_regular(path, f"{kind} claim")
    return _parse_claim(
        data,
        kind=kind,
        schema=schema,
        identity=identity,
        key=key,
        path=path,
    )


def inspect_boot_prefix_claim(
    root: Path,
    current_preimage_sha256: str,
    current_preimage_size: int = BOOT_PREFIX_SIZE,
) -> ClaimRecord | None:
    identity, key = boot_prefix_claim_identity(
        current_preimage_sha256, current_preimage_size
    )
    return _inspect(
        boot_prefix_claim_path(root, key),
        kind="boot-prefix",
        schema=BOOT_PREFIX_CLAIM_SCHEMA,
        identity=identity,
        key=key,
    )


def inspect_native_transition_claim(root: Path, boot_id: str) -> ClaimRecord | None:
    identity, key = native_transition_claim_identity(boot_id)
    return _inspect(
        native_transition_claim_path(root, key),
        kind="native-transition",
        schema=NATIVE_TRANSITION_CLAIM_SCHEMA,
        identity=identity,
        key=key,
    )


def claim_boot_prefix(
    root: Path,
    *,
    current_preimage_sha256: str,
    current_preimage_size: int = BOOT_PREFIX_SIZE,
    experiment_id: str,
    provenance: Mapping[str, object] | None = None,
) -> ClaimRecord:
    identity, key = boot_prefix_claim_identity(
        current_preimage_sha256, current_preimage_size
    )
    path = boot_prefix_claim_path(root, key)
    existing = inspect_boot_prefix_claim(root, current_preimage_sha256, current_preimage_size)
    if existing is not None:
        raise PhysicalClaimAlreadyExists(
            "boot-prefix physical claim already exists; replay forbidden", existing
        )
    try:
        data = create_boot_prefix_claim(
            path,
            identity=identity,
            key_sha256=key,
            experiment_id=experiment_id,
            provenance=provenance,
        )
    except PhysicalClaimAlreadyExists as exc:
        existing = inspect_boot_prefix_claim(
            root, current_preimage_sha256, current_preimage_size
        )
        raise PhysicalClaimAlreadyExists(str(exc), existing) from exc
    return ClaimRecord(
        kind="boot-prefix",
        path=path,
        key_sha256=key,
        identity=identity,
        record=json.loads(data.decode("utf-8")),
        data=data,
    )


def claim_native_transition(
    root: Path,
    *,
    boot_id: str,
    experiment_id: str,
    provenance: Mapping[str, object] | None = None,
) -> ClaimRecord:
    identity, key = native_transition_claim_identity(boot_id)
    path = native_transition_claim_path(root, key)
    existing = inspect_native_transition_claim(root, boot_id)
    if existing is not None:
        raise PhysicalClaimAlreadyExists(
            "native transition physical claim already exists; replay forbidden", existing
        )
    try:
        data = create_native_transition_claim(
            path,
            identity=identity,
            key_sha256=key,
            experiment_id=experiment_id,
            provenance=provenance,
        )
    except PhysicalClaimAlreadyExists as exc:
        existing = inspect_native_transition_claim(root, boot_id)
        raise PhysicalClaimAlreadyExists(str(exc), existing) from exc
    return ClaimRecord(
        kind="native-transition",
        path=path,
        key_sha256=key,
        identity=identity,
        record=json.loads(data.decode("utf-8")),
        data=data,
    )


def validate_normal_remapper_continuation(
    claim: ClaimRecord,
    *,
    root: Path,
    journal_path: Path,
    profile: str,
    predecessor_sha256: str,
    predecessor_size: int = BOOT_PREFIX_SIZE,
) -> None:
    """Validate the sole safe recovery continuation from a normal claim.

    Recovery may reuse a boot-prefix claim only when its provenance identifies
    the canonical normal-flash journal and that journal is now an exact
    ambiguous post-marker source.  Any other owner/profile/path/partial state
    is rejected by the caller rather than interpreted as a new opportunity.
    """

    if claim.kind != "boot-prefix":
        raise PhysicalClaimError("claim kind is not boot-prefix")
    provenance = claim.record.get("provenance")
    if not isinstance(provenance, Mapping):
        raise PhysicalClaimError("normal remapper claim provenance is missing")
    if provenance.get("owner_kind") != "normal-remapper":
        raise PhysicalClaimError("boot-prefix claim owner is not normal remapper")
    if provenance.get("profile") != profile:
        raise PhysicalClaimError("normal remapper claim profile differs")
    if provenance.get("predecessor_sha256") != predecessor_sha256:
        raise PhysicalClaimError("normal remapper claim predecessor differs")
    if provenance.get("predecessor_size") != predecessor_size:
        raise PhysicalClaimError("normal remapper claim predecessor size differs")
    if profile not in V024_IMAGE_HASHES:
        raise PhysicalClaimError("normal remapper claim profile is not fixed")
    if provenance.get("image_sha256") != V024_IMAGE_HASHES[profile]:
        raise PhysicalClaimError("normal remapper claim intended image differs")
    if provenance.get("image_size") != BOOT_PREFIX_SIZE:
        raise PhysicalClaimError("normal remapper claim intended image size differs")
    expected_path = Path(journal_path).resolve(strict=False)
    supplied_path = provenance.get("journal_path")
    if not isinstance(supplied_path, str) or Path(supplied_path) != expected_path:
        raise PhysicalClaimError("normal remapper claim journal path differs")
    expected_root = Path(root).resolve(strict=False)
    canonical_path = (
        expected_root
        / "evidence"
        / "private"
        / f"verification-024-remapper-boot-flash-{profile}.journal.json"
    )
    if expected_path != canonical_path:
        raise PhysicalClaimError("normal remapper claim journal is not canonical")
    journal_path = expected_path
    _reject_symlink_components(journal_path, "normal remapper journal")
    data, _ = _read_regular(journal_path, "normal remapper journal")
    journal = _strict_json_object(data, "normal remapper journal")
    required = {
        "schema": "sdm855-a90-remapper-boot-flash-private-v1",
        "status": "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED",
        "profile": profile,
        "allowed_predecessors": V024_PREDECESSORS[profile],
        "predecessor_sha256": predecessor_sha256,
        "predecessor_size": predecessor_size,
        "image_sha256": V024_IMAGE_HASHES[profile],
        "image_size": BOOT_PREFIX_SIZE,
        "remote_staging": V024_STAGING[profile],
        "effect_armed": True,
        "effect_dispatched": True,
        "effect_replayed": False,
        "write_count": 1,
        "current_state": "UNKNOWN",
        "staging_cleanup_deferred": True,
        "reconcile_required": True,
    }
    for key, expected in required.items():
        if journal.get(key) != expected:
            raise PhysicalClaimError(
                f"normal remapper journal is not the exact ambiguous source: {key}"
            )


__all__ = [
    "BOOT_ID_RE",
    "BOOT_PREFIX_BLOCK_COUNT",
    "BOOT_PREFIX_BLOCK_SIZE",
    "BOOT_PREFIX_CLAIM_PREFIX",
    "BOOT_PREFIX_CLAIM_SCHEMA",
    "BOOT_PREFIX_PARTITION",
    "BOOT_PREFIX_SIZE",
    "ClaimRecord",
    "MAX_CLAIM_BYTES",
    "NATIVE_TRANSITION_CLAIM_PREFIX",
    "NATIVE_TRANSITION_CLAIM_SCHEMA",
    "NATIVE_TRANSITION_RESOURCE",
    "V024_IMAGE_HASHES",
    "V024_PREDECESSORS",
    "V024_STAGING",
    "PhysicalClaimAlreadyExists",
    "PhysicalClaimError",
    "PhysicalClaimPartial",
    "boot_prefix_claim_identity",
    "boot_prefix_claim_path",
    "claim_boot_prefix",
    "claim_native_transition",
    "create_boot_prefix_claim",
    "create_native_transition_claim",
    "inspect_boot_prefix_claim",
    "inspect_native_transition_claim",
    "native_transition_claim_identity",
    "native_transition_claim_path",
    "sha256",
    "validate_normal_remapper_continuation",
]
