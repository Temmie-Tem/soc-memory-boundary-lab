#!/usr/bin/env python3
"""Read the pinned Verification 024 control predecessor for R2.

Phase R2-A1 is deliberately a host-only input boundary.  It resolves one
pre-registered public/private triplet, reads each inode through a no-follow
descriptor, and applies byte-level integrity checks.  The pure A2a semantic
validator then consumes that private in-memory triplet and returns only a
deterministic, redacted capsule body.  No public builder, Git subprocess,
device, or transport authority is present in this phase.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat
from typing import Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]

PREDECESSOR_ID = "verification-024-control"
ACTIVE_CONTROL_ID = "verification-024-control-r2"

# These are intentionally relative to the repository root.  Keeping the
# namespace fixed means a caller cannot select an alternate producer by
# supplying a path or a basename.  The aliases below are kept descriptive and
# path-only; no absolute path is part of the returned result.
PREDECESSOR_PUBLIC_RELATIVE_PATH = Path(
    "evidence/manifests/verification-024-control.manifest.json"
)
PREDECESSOR_RAW_RELATIVE_PATH = Path(
    "evidence/private/verification-024-control.json"
)
PREDECESSOR_JOURNAL_RELATIVE_PATH = Path(
    "evidence/private/verification-024-control.journal.json"
)

# Short aliases make the fixed contract easy to inspect without changing its
# meaning.  They are Path objects containing only relative names.
PUBLIC_RELATIVE_PATH = PREDECESSOR_PUBLIC_RELATIVE_PATH
RAW_RELATIVE_PATH = PREDECESSOR_RAW_RELATIVE_PATH
JOURNAL_RELATIVE_PATH = PREDECESSOR_JOURNAL_RELATIVE_PATH
PREDECESSOR_PUBLIC_PATH = PREDECESSOR_PUBLIC_RELATIVE_PATH
PREDECESSOR_RAW_PATH = PREDECESSOR_RAW_RELATIVE_PATH
PREDECESSOR_JOURNAL_PATH = PREDECESSOR_JOURNAL_RELATIVE_PATH

FIXED_RELATIVE_PATHS: Mapping[str, Path] = {
    "public": PREDECESSOR_PUBLIC_RELATIVE_PATH,
    "raw": PREDECESSOR_RAW_RELATIVE_PATH,
    "journal": PREDECESSOR_JOURNAL_RELATIVE_PATH,
}

# Canonical byte pins supplied by the predecessor.  Keep scalar constants as
# well as role mappings: tests and later host-only phases can replace either a
# complete role pin or an individual scalar when building an isolated fixture.
PUBLIC_SHA256 = "fcdeaf36d10c112751c0c429eb9834b140bbefb7e83ad18051f9f73e4f237af4"
PUBLIC_SIZE_BYTES = 3715
PUBLIC_SIZE = PUBLIC_SIZE_BYTES
PUBLIC_MODE = 0o644

RAW_SHA256 = "4adbdfccb68232f42e6c6a60a57c8acb0be98db5ba01d77db4750993c11ca649"
RAW_SIZE_BYTES = 4952
RAW_SIZE = RAW_SIZE_BYTES
RAW_MODE = 0o600

JOURNAL_SHA256 = "e6d4589be21c11601a4f0be91a1a3d992b66b17dfe80a896a8d8f176ebb77b04"
JOURNAL_SIZE_BYTES = 4662
JOURNAL_SIZE = JOURNAL_SIZE_BYTES
JOURNAL_MODE = 0o600

PUBLIC_PIN = {
    "sha256": PUBLIC_SHA256,
    "size_bytes": PUBLIC_SIZE_BYTES,
    "mode": PUBLIC_MODE,
}
RAW_PIN = {
    "sha256": RAW_SHA256,
    "size_bytes": RAW_SIZE_BYTES,
    "mode": RAW_MODE,
}
JOURNAL_PIN = {
    "sha256": JOURNAL_SHA256,
    "size_bytes": JOURNAL_SIZE_BYTES,
    "mode": JOURNAL_MODE,
}

_DEFAULT_PINS = {
    "public": dict(PUBLIC_PIN),
    "raw": dict(RAW_PIN),
    "journal": dict(JOURNAL_PIN),
}

# ``TRIPLET_PINS`` is the canonical role map.  ``PINS`` and
# ``PREDECESSOR_PINS`` are compatibility aliases for host fixtures that patch
# a mapping rather than the scalar values above.  ``_pin_for`` detects a
# patched mapping while retaining scalar patchability.
TRIPLET_PINS = {
    "public": PUBLIC_PIN,
    "raw": RAW_PIN,
    "journal": JOURNAL_PIN,
}
PINS = TRIPLET_PINS
PREDECESSOR_PINS = TRIPLET_PINS

# Every input is tiny today, but the bound is part of the reader contract.  A
# read asks for at most one bounded chunk at a time and probes one byte beyond
# the bound, so a growing file cannot turn this helper into an allocation
# oracle.
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = MAX_FILE_BYTES
MAX_RECEIPT_BYTES = MAX_FILE_BYTES
READ_CHUNK_BYTES = 64 * 1024


class ControlRetryError(ValueError):
    """Raised when the fixed predecessor triplet cannot be read safely."""


# A few callers use a generic input-error name; keep it an alias, not a
# second exception hierarchy.
RetryInputError = ControlRetryError
TripletReadError = ControlRetryError


def _absolute_lexical(path: Path | str) -> Path:
    """Return an absolute lexical path without resolving symlinks.

    Reject ``..`` from the caller's original path before ``abspath`` can
    normalize it.  A symlink followed by ``..`` must not be able to disguise a
    path that would otherwise appear beneath the fixed root.
    """

    try:
        original = Path(os.fspath(path))
    except (TypeError, ValueError) as exc:
        raise ControlRetryError("path is not a valid filesystem path") from exc
    if ".." in original.parts:
        raise ControlRetryError("path may not contain '..' components")
    return Path(os.path.abspath(os.fspath(original)))


def _reject_symlink_components(path: Path | str, label: str) -> Path:
    """Reject every existing symlink in ``path``, including the final leaf.

    ``Path.resolve`` is intentionally not used here: resolving would turn a
    forbidden alias into an apparently canonical path.  ``lstat`` lets us
    inspect the directory entries themselves.  Missing components are left for
    the subsequent open to report, which keeps the resolver useful for a
    synthetic fixture while still refusing every present link.
    """

    absolute = _absolute_lexical(path)
    anchor = Path(absolute.anchor or os.sep)
    cursor = anchor
    # ``absolute.parts`` is ('/', 'tmp', ...) on POSIX.  Starting at the
    # anchor and appending the remaining components also handles a relative
    # caller after lexical conversion.
    for component in absolute.parts[1:]:
        cursor = cursor / component
        try:
            info = os.lstat(cursor)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ControlRetryError(
                f"{label} component cannot be inspected: {cursor}"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise ControlRetryError(f"{label} component is a symlink: {cursor}")
    return absolute


def _path_under_root(path: Path, root: Path, label: str) -> Path:
    """Bind a lexical fixed path beneath a lexical fixed root."""

    try:
        path.relative_to(root)
    except ValueError as exc:  # pragma: no cover - fixed constants guard this
        raise ControlRetryError(f"{label} escapes the fixed repository root") from exc
    return _reject_symlink_components(path, label)


def _resolve_fixed_paths(root: Path | str = REPO_ROOT) -> dict[str, Path]:
    """Resolve the three pre-registered predecessor paths under ``root``.

    The returned values are absolute *internal* handles for the subsequent
    descriptor opens.  ``stable_read_triplet`` intentionally does not add
    those resolved paths to its result; reader-added artifact metadata is
    limited to basenames and byte metadata.
    """

    root_path = _reject_symlink_components(root, "repository root")
    try:
        root_info = os.lstat(root_path)
    except OSError as exc:
        raise ControlRetryError("repository root cannot be inspected") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise ControlRetryError("repository root is not a directory")

    resolved: dict[str, Path] = {}
    for role, relative in FIXED_RELATIVE_PATHS.items():
        # The relative constants are fixed in this module.  The explicit
        # check makes accidental future edits fail closed if a ``..`` escapes.
        if relative.is_absolute():
            raise ControlRetryError(f"{role} path is not relative")
        path = _absolute_lexical(root_path / relative)
        resolved[role] = _path_under_root(path, root_path, f"{role} predecessor")
    return resolved

def _open_readonly_nofollow(path: Path) -> int:
    """Open a fixed file through no-follow directory descriptors.

    Passing ``O_NOFOLLOW`` only to a whole absolute pathname protects the leaf;
    walking each parent with ``openat`` also prevents a parent-directory link
    from redirecting the read after the lexical lstat pass.  ``O_NONBLOCK`` is
    added only to avoid hanging on a FIFO before its regular-file check; it is
    harmless for ordinary files.
    """

    absolute = _absolute_lexical(path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise ControlRetryError("O_NOFOLLOW is unavailable")
    directory_flags = os.O_RDONLY | nofollow
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    leaf_flags = os.O_RDONLY | nofollow
    leaf_flags |= getattr(os, "O_CLOEXEC", 0)
    leaf_flags |= getattr(os, "O_NONBLOCK", 0)

    parts = absolute.parts
    if len(parts) < 2:  # The fixed leaves always have parents.
        raise ControlRetryError("fixed predecessor path has no parent")

    try:
        parent_fd = os.open(parts[0], directory_flags)
    except OSError as exc:
        raise ControlRetryError(f"cannot open fixed parent of {absolute}") from exc
    try:
        for component in parts[1:-1]:
            try:
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            except OSError as exc:
                raise ControlRetryError(
                    f"cannot open fixed parent component {component}"
                ) from exc
            os.close(parent_fd)
            parent_fd = next_fd
        try:
            return os.open(parts[-1], leaf_flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ControlRetryError(f"cannot open fixed predecessor leaf {absolute}") from exc
    finally:
        os.close(parent_fd)


def _pin_for(role: str) -> dict[str, object]:
    """Read the current role pin, allowing isolated tests to patch pins."""

    # Prefer a mapping that a fixture explicitly replaced or mutated.  The
    # scalar constants remain the default source so patching PUBLIC_SHA256 (or
    # its size/mode peer) is equally effective.
    for name in ("TRIPLET_PINS", "PINS", "PREDECESSOR_PINS"):
        candidate = globals().get(name)
        if isinstance(candidate, Mapping) and candidate != _DEFAULT_PINS:
            value = candidate.get(role)
            if isinstance(value, Mapping):
                return dict(value)

    # Also honor replacement/mutation of an individual role mapping.  This is
    # distinct from the role-map aliases above when a test assigns a new dict
    # to PUBLIC_PIN/RAW_PIN/JOURNAL_PIN.
    role_pin_name = {
        "public": "PUBLIC_PIN",
        "raw": "RAW_PIN",
        "journal": "JOURNAL_PIN",
    }.get(role)
    if role_pin_name is not None:
        candidate = globals().get(role_pin_name)
        if isinstance(candidate, Mapping) and candidate != _DEFAULT_PINS[role]:
            return dict(candidate)

    if role == "public":
        return {
            "sha256": PUBLIC_SHA256,
            "size_bytes": (
                PUBLIC_SIZE_BYTES
                if PUBLIC_SIZE_BYTES != _DEFAULT_PINS["public"]["size_bytes"]
                else PUBLIC_SIZE
            ),
            "mode": PUBLIC_MODE,
        }
    if role == "raw":
        return {
            "sha256": RAW_SHA256,
            "size_bytes": (
                RAW_SIZE_BYTES
                if RAW_SIZE_BYTES != _DEFAULT_PINS["raw"]["size_bytes"]
                else RAW_SIZE
            ),
            "mode": RAW_MODE,
        }
    if role == "journal":
        return {
            "sha256": JOURNAL_SHA256,
            "size_bytes": (
                JOURNAL_SIZE_BYTES
                if JOURNAL_SIZE_BYTES != _DEFAULT_PINS["journal"]["size_bytes"]
                else JOURNAL_SIZE
            ),
            "mode": JOURNAL_MODE,
        }
    raise ControlRetryError(f"unknown predecessor role: {role}")


def _pin_value(pin: Mapping[str, object], key: str, role: str) -> object:
    try:
        value = pin[key]
    except KeyError as exc:
        raise ControlRetryError(f"{role} pin lacks {key}") from exc
    return value


def _stable_read_bytes(path: Path, role: str, pin: Mapping[str, object]) -> tuple[bytes, dict[str, object]]:
    """Read one pinned inode and return bytes plus redacted metadata."""

    expected_mode = _pin_value(pin, "mode", role)
    expected_size = _pin_value(pin, "size_bytes", role)
    expected_sha256 = _pin_value(pin, "sha256", role)
    if type(expected_mode) is not int or expected_mode < 0 or expected_mode > 0o7777:
        raise ControlRetryError(f"{role} mode pin is invalid")
    if type(expected_size) is not int or expected_size < 0:
        raise ControlRetryError(f"{role} size pin is invalid")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise ControlRetryError(f"{role} SHA-256 pin is invalid")

    _reject_symlink_components(path, f"{role} predecessor")
    fd = _open_readonly_nofollow(path)
    try:
        try:
            before = os.fstat(fd)
        except OSError as exc:
            raise ControlRetryError(f"{role} cannot be stat-ed") from exc

        if not stat.S_ISREG(before.st_mode):
            raise ControlRetryError(f"{role} is not a regular file")
        if stat.S_IMODE(before.st_mode) != expected_mode:
            raise ControlRetryError(f"{role} mode is not exact")
        if before.st_uid != os.getuid() or before.st_gid != os.getgid():
            raise ControlRetryError(f"{role} owner is not the current uid/gid")
        if before.st_nlink != 1:
            raise ControlRetryError(f"{role} inode has unexpected link count")
        if before.st_size < 0 or before.st_size != expected_size:
            raise ControlRetryError(f"{role} size is not exact")
        if before.st_size > MAX_FILE_BYTES:
            raise ControlRetryError(f"{role} exceeds the bounded file size")

        chunks: list[bytes] = []
        total = 0
        while True:
            # The +1 probe catches a file that grows just beyond the bound;
            # the read result is still checked before it is retained.
            request_size = min(
                READ_CHUNK_BYTES,
                max(1, MAX_FILE_BYTES - total + 1),
            )
            try:
                chunk = os.read(fd, request_size)
            except OSError as exc:
                raise ControlRetryError(f"{role} cannot be read") from exc
            if not chunk:
                break
            if not isinstance(chunk, bytes):  # defensive for mocked readers
                raise ControlRetryError(f"{role} returned a non-byte chunk")
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise ControlRetryError(f"{role} exceeds the bounded file size")

        try:
            after = os.fstat(fd)
        except OSError as exc:
            raise ControlRetryError(f"{role} cannot be re-stat-ed") from exc
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
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
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or total != after.st_size:
            raise ControlRetryError(f"{role} changed while being read")

        data = b"".join(chunks)
        if len(data) != expected_size:
            raise ControlRetryError(f"{role} byte size is not exact")
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected_sha256:
            raise ControlRetryError(f"{role} SHA-256 is not exact")
        return data, {
            "basename": path.name,
            "size_bytes": len(data),
            "sha256": digest,
        }
    finally:
        os.close(fd)


def _strict_json_object(data: bytes, role: str) -> dict[str, object]:
    """Decode one strict UTF-8 JSON object with unique keys and finite values."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ControlRetryError(f"{role} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ControlRetryError(f"{role} contains non-finite JSON number: {value}")

    def reject_nonfinite(value: object) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ControlRetryError(f"{role} contains non-finite JSON number")
        if isinstance(value, dict):
            for nested in value.values():
                reject_nonfinite(nested)
        elif isinstance(value, list):
            for nested in value:
                reject_nonfinite(nested)

    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except ControlRetryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlRetryError(f"{role} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ControlRetryError(f"{role} JSON root is not an object")
    reject_nonfinite(value)
    return value


def _stable_read_triplet_for_root(root: Path | str) -> dict[str, object]:
    """Read the fixed triplet beneath a synthetic/internal root.

    This underscore-prefixed seam exists only for host tests and A2's
    controlled fixture harness.  Production callers use
    :func:`stable_read_triplet`, which has no root selector.
    """

    paths = _resolve_fixed_paths(root)
    values: dict[str, dict[str, object]] = {}
    metadata: dict[str, dict[str, object]] = {}
    for role in ("public", "raw", "journal"):
        data, info = _stable_read_bytes(paths[role], role, _pin_for(role))
        values[role] = _strict_json_object(data, role)
        metadata[role] = info

    # The parsed dictionaries are PRIVATE IN-MEMORY A2 inputs.  Callers must
    # not publish or log raw/journal contents, and this structure is not a
    # public capsule.  Reader-added artifact metadata remains redacted to
    # basename/hash/size only.
    return {
        "predecessor_id": PREDECESSOR_ID,
        "active_control_id": ACTIVE_CONTROL_ID,
        "public": values["public"],
        "raw": values["raw"],
        "journal": values["journal"],
        "artifacts": metadata,
    }


def stable_read_triplet() -> dict[str, object]:
    """Read and strictly parse the fixed predecessor public/raw/journal triplet.

    The production API is bound to module ``REPO_ROOT`` and has no caller
    supplied root/path selector.  The result contains three PRIVATE
    IN-MEMORY parsed dictionaries for A2 and one metadata record for each byte
    stream.  Raw/journal values must not be published or logged; this return is
    not a public capsule.  Reader-added artifact metadata is limited to
    ``basename``, ``size_bytes`` and ``sha256``; raw byte payloads and
    reader-resolved absolute input paths are not added.  No semantic field
    validation is performed in this phase.
    """

    return _stable_read_triplet_for_root(REPO_ROOT)


# A descriptive alias is useful to callers that treat the operation as a
# loader.  It does not create a second implementation seam.
read_triplet = stable_read_triplet


# ---------------------------------------------------------------------------
# Phase R2-A2: pure predecessor semantic capsule

CAPSULE_SCHEMA = "sdm855-a90-v024-control-predecessor-capsule-v1"
CAPSULE_PHASE = "R2-A2"

# These are byte pins only at this stage.  A2b is responsible for obtaining
# the exact historical Git objects and verifying these values.  In particular,
# no ``verified`` or ``verification_pending`` claim is emitted here.
PRODUCER_COMMIT = "6eaad666a7d666fdf50955d372e9b837bcb326ed"
PRODUCER_SOURCE_PINS: Mapping[str, Mapping[str, object]] = {
    "inline": {
        "relative_path": "tools/a90_inline_remapper_mid_probe.py",
        "basename": "a90_inline_remapper_mid_probe.py",
        "sha256": "0b171d4ca0b5a2f77b01745a285a67eea3436c9f78eb1d800ab0792bf0818c63",
        "size_bytes": 160591,
    },
    "autohud": {
        "relative_path": "tools/a90_autohud_arbitration.py",
        "basename": "a90_autohud_arbitration.py",
        "sha256": "5da86cb927543e60626a679cbd949348c4f377c91148e59669990b6b3a6ba926",
        "size_bytes": 8213,
    },
    "transport": {
        "relative_path": "tools/a90_pa28_live.py",
        "basename": "a90_pa28_live.py",
        "sha256": "0f50a20453f00a6f647d52cc2c3cd10ba52f8869d6b9264d5b9c47671197bc66",
        "size_bytes": 150104,
    },
}

CANDIDATE_SHA256 = "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247"
CANDIDATE_SIZE_BYTES = 60882944
FIXED_OP = 4
FIXED_OP_ARGS: list[object] = []
FIXED_OP_BUFFER_SHA256 = "7cb5cf5aa907dce3b48ddc5dce8f296782ac2d1b24d18cb55fa54d45cb86c6b4"
FIXED_OP_BUFFER_SIZE = 88
FLASH_JOURNAL_SHA256 = "77055c1fb683541f31f22bd1232c1a947b38c401749383a70f826ec7ab12aa9e"
FLASH_JOURNAL_SIZE = 6434
FLASH_PREDECESSOR_SHA256 = "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb"
FLASH_COMPLETED_UTC = "2026-08-28T03:39:53+00:00"
INCIDENT_STARTED_UTC = "2026-08-28T04:59:43+00:00"
INCIDENT_COMPLETED_UTC = INCIDENT_STARTED_UTC
TRANSPORT_MODULE = "tools.a90_pa28_live"
TRANSPORT_SOURCE = "tools/a90_pa28_live.py"
TRANSPORT_SOURCE_SHA256 = "0f50a20453f00a6f647d52cc2c3cd10ba52f8869d6b9264d5b9c47671197bc66"
TRANSPORT_SOURCE_SIZE = 150104

_CAPSULE_TOP_KEYS = frozenset(
    {
        "schema",
        "phase",
        "predecessor_id",
        "active_control_id",
        "provenance",
        "artifacts",
        "semantic",
        "claims",
    }
)
_CAPSULE_SEMANTIC_KEYS = frozenset(
    {
        "identity",
        "candidate",
        "fixed_op",
        "flash",
        "transport",
        "failure",
        "legacy_frame",
        "health",
        "hud",
        "effect",
    }
)
_CAPSULE_CLAIM_KEYS = frozenset(
    {
        "effect_grades",
        "mmio_effect",
        "stophud_state_change",
        "partial_transport_retained_private_is_authority",
        "historical_bridge_is_authority",
        "live_authority",
        "replay_allowed",
        "old_id_reuse_allowed",
        "fallback_allowed",
        "legacy_marker",
    }
)


def _sha256_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ControlRetryError(f"{label} is not an exact lowercase SHA-256")
    return value


def canonical_byte_descriptor(metadata: Mapping[str, object]) -> dict[str, object]:
    """Return the A3-safe basename/size/hash projection of one byte artifact."""

    if type(metadata) is not dict:
        raise ControlRetryError("byte metadata is not an object")
    basename = metadata.get("basename")
    size_bytes = metadata.get("size_bytes")
    digest = metadata.get("sha256")
    if (
        not isinstance(basename, str)
        or not basename
        or basename in {".", ".."}
        or "/" in basename
        or "\\" in basename
    ):
        raise ControlRetryError("byte metadata basename is not a safe basename")
    if type(size_bytes) is not int or size_bytes < 0:
        raise ControlRetryError("byte metadata size is not an exact integer")
    digest = _sha256_text(digest, "byte metadata SHA-256")
    return {"basename": basename, "size_bytes": size_bytes, "sha256": digest}


def canonical_capsule_bytes(capsule: Mapping[str, object]) -> bytes:
    """Serialize one capsule with deterministic, strict JSON bytes."""

    if type(capsule) is not dict:
        raise ControlRetryError("capsule is not an object")
    try:
        return (
            json.dumps(
                capsule,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ControlRetryError("capsule is not deterministic JSON") from exc


def _require_mapping(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ControlRetryError(f"{label} is not an object")
    return value


def _require_exact_keys(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
    mapping = _require_mapping(value, label)
    if set(mapping) != set(keys):
        raise ControlRetryError(f"{label} fields are not exact")
    return mapping


_MISSING = object()


def _require_value(mapping: Mapping[str, object], key: str, expected: object, label: str) -> object:
    actual = mapping.get(key, _MISSING)
    if expected is None:
        if actual is not None:
            raise ControlRetryError(f"{label}.{key} is not exactly null")
        return actual
    if type(actual) is not type(expected) or actual != expected:
        raise ControlRetryError(f"{label}.{key} is not exact")
    return actual


def _require_false(mapping: Mapping[str, object], key: str, label: str) -> None:
    _require_value(mapping, key, False, label)


def _require_true(mapping: Mapping[str, object], key: str, label: str) -> None:
    _require_value(mapping, key, True, label)


def _require_null(mapping: Mapping[str, object], key: str, label: str) -> None:
    _require_value(mapping, key, None, label)


def _require_zero(mapping: Mapping[str, object], key: str, label: str) -> None:
    _require_value(mapping, key, 0, label)


def _require_artifact_descriptor(value: object, role: str) -> dict[str, object]:
    descriptor = _require_exact_keys(
        value, frozenset({"basename", "size_bytes", "sha256"}), f"artifact {role}"
    )
    descriptor = canonical_byte_descriptor(descriptor)
    expected_basenames = {
        "public": "verification-024-control.manifest.json",
        "raw": "verification-024-control.json",
        "journal": "verification-024-control.journal.json",
    }
    if role in expected_basenames and descriptor["basename"] != expected_basenames[role]:
        raise ControlRetryError(f"artifact {role} basename is not the fixed predecessor file")
    return descriptor


def _require_panic_transition(value: object, label: str) -> dict[str, object]:
    mapping = _require_exact_keys(
        value,
        frozenset(
            {
                "before",
                "proof_frame_ids",
                "restore_deferred",
                "restore_write_attempted",
                "restored",
                "zero_set",
                "zero_verified",
                "zero_write_attempted",
            }
        ),
        label,
    )
    _require_null(mapping, "before", label)
    _require_value(mapping, "proof_frame_ids", [], label)
    for key in (
        "restore_deferred",
        "restore_write_attempted",
        "restored",
        "zero_set",
        "zero_verified",
        "zero_write_attempted",
    ):
        _require_false(mapping, key, label)
    return mapping


def _require_health(value: object, label: str) -> dict[str, object]:
    """Require the old skipped health projection with exact JSON types."""

    mapping = _require_exact_keys(
        value,
        frozenset({"ok", "reason", "skipped"}),
        label,
    )
    _require_value(mapping, "ok", False, label)
    _require_value(mapping, "reason", "target_not_bound", label)
    _require_value(mapping, "skipped", True, label)
    return mapping


def _require_error(value: object, label: str) -> dict[str, object]:
    mapping = _require_exact_keys(
        value,
        frozenset(
            {
                "begin",
                "end",
                "exception_text",
                "exception_type",
                "payload_base64",
                "payload_bounded",
                "payload_sha256",
                "payload_size",
                "transcript_base64",
                "transcript_bounded",
                "transcript_sha256",
                "transcript_size",
            }
        ),
        label,
    )
    for key in (
        "begin",
        "end",
        "payload_base64",
        "payload_sha256",
        "payload_size",
        "transcript_base64",
        "transcript_sha256",
        "transcript_size",
    ):
        _require_null(mapping, key, label)
    _require_value(mapping, "exception_text", "stophud attempt payload is not empty", label)
    _require_value(mapping, "exception_type", "ProbeError", label)
    _require_true(mapping, "payload_bounded", label)
    _require_true(mapping, "transcript_bounded", label)
    return mapping


def _require_legacy_frame(value: object, label: str) -> dict[str, object]:
    mapping = _require_exact_keys(
        value,
        frozenset(
            {
                "argv",
                "attempt",
                "evidence_id",
                "partial_begin",
                "partial_end",
                "partial_payload_sha256",
                "partial_payload_size",
                "partial_transcript_sha256",
                "partial_transcript_size",
                "transport_error",
                "transport_error_type",
            }
        ),
        label,
    )
    _require_value(mapping, "argv", ["stophud"], label)
    _require_value(mapping, "attempt", 1, label)
    _require_value(mapping, "evidence_id", "stophud_1", label)
    for key in (
        "partial_begin",
        "partial_end",
        "partial_payload_sha256",
        "partial_payload_size",
        "partial_transcript_sha256",
        "partial_transcript_size",
    ):
        _require_null(mapping, key, label)
    _require_value(mapping, "transport_error", "stophud attempt payload is not empty", label)
    _require_value(mapping, "transport_error_type", "ProbeError", label)
    return mapping


def _require_flash_journal(value: object, label: str) -> dict[str, object]:
    mapping = _require_exact_keys(
        value,
        frozenset(
            {
                "image_sha256",
                "path",
                "predecessor_sha256",
                "profile",
                "readback_sha256",
                "sha256",
                "size",
            }
        ),
        label,
    )
    path = mapping.get("path")
    if not isinstance(path, str) or Path(path).name != "verification-024-remapper-boot-flash-control.journal.json":
        raise ControlRetryError(f"{label}.path is not the control flash journal")
    _require_value(mapping, "image_sha256", CANDIDATE_SHA256, label)
    _require_value(mapping, "predecessor_sha256", FLASH_PREDECESSOR_SHA256, label)
    _require_value(mapping, "profile", "control", label)
    _require_value(mapping, "readback_sha256", CANDIDATE_SHA256, label)
    _require_value(mapping, "sha256", FLASH_JOURNAL_SHA256, label)
    _require_value(mapping, "size", FLASH_JOURNAL_SIZE, label)
    return mapping


# The predecessor is deliberately validated against the producer's complete
# three-record shape.  A byte pin by itself proves only that some bytes were
# retained; these exact key sets prevent an A1 fixture from becoming a
# different evidence universe by adding an unbound summary or frame field.
_PUBLIC_KEYS = frozenset(
    {
        "arbitrary_address_input",
        "automatic_retries",
        "boot_id_before_read_sha256",
        "bridge_bound",
        "candidate_sha256",
        "candidate_size",
        "claim_boundary",
        "clean_negative",
        "cleanup_ok",
        "completed_utc",
        "control_manifest",
        "controller_writes",
        "current_boot_attestation",
        "device_state_write",
        "dispatch_count",
        "dispatch_failed",
        "dispatch_returned",
        "effect_ambiguous",
        "effect_dispatched",
        "effect_replayed",
        "experiment_id",
        "failed_stage",
        "final_bridge_bound",
        "fixed_op",
        "flash_completed_utc",
        "flash_image_sha256",
        "flash_journal_bound",
        "flash_journal_sha256",
        "flash_journal_size",
        "flash_predecessor_sha256",
        "flash_profile",
        "flash_readback_sha256",
        "generic_call_target",
        "health_after_ok",
        "journal_sha256",
        "journal_size",
        "memory_or_mmio_writes",
        "mode",
        "op",
        "op_args",
        "outcome",
        "panic_on_oops_before",
        "panic_on_oops_restored",
        "panic_on_oops_zero_set",
        "panic_on_oops_zero_verified",
        "panic_restore_deferred",
        "panic_transition",
        "partial_transport_retained_private",
        "partition_writes",
        "private_record",
        "promotion",
        "protected_memory_read",
        "raw_cmdline_omitted",
        "raw_snapshot_sha256",
        "raw_snapshot_size",
        "raw_value_omitted",
        "reboot_dispatched",
        "requires_last_kmsg_rollback_health",
        "returned_value_present",
        "returned_value_sha256",
        "runtime",
        "schema",
        "security_classification",
        "semantic_claim",
        "serial_identity_omitted",
        "smc",
        "soc",
        "started_utc",
        "stophud_accepted",
        "stophud_busy_retries",
        "target_evaluation",
        "target_model",
        "target_verified",
        "temporary_sysctl_write",
        "temporary_sysctl_write_attempted",
        "transport_module",
        "transport_no_value",
        "transport_source",
        "transport_source_sha256",
        "transport_source_size",
        "transport_source_verified",
    }
)

_RAW_KEYS = frozenset(
    {
        "automatic_retries",
        "boot_id_before_read",
        "boot_id_before_read_sha256",
        "bridge_binding",
        "candidate_sha256",
        "candidate_size",
        "cleanup_ok",
        "completed_utc",
        "control_manifest",
        "controller_writes",
        "current_boot_attestation",
        "device_state_write",
        "dispatch_count",
        "dispatch_failed",
        "dispatch_returned",
        "effect_ambiguous",
        "effect_dispatched",
        "effect_replayed",
        "error",
        "experiment_id",
        "failed_stage",
        "final_bridge_bound",
        "fixed_op_measurement",
        "flash_journal",
        "frames",
        "health_after",
        "memory_or_mmio_writes",
        "mode",
        "op",
        "op_args",
        "outcome",
        "panic_on_oops_before",
        "panic_on_oops_restored",
        "panic_on_oops_zero_set",
        "panic_on_oops_zero_verified",
        "panic_restore_deferred",
        "panic_transition",
        "partition_writes",
        "promotion",
        "protected_memory_read",
        "reboot_dispatched",
        "schema",
        "security_classification",
        "semantic_claim_key_sha256",
        "semantic_claim_path",
        "semantic_claim_sha256",
        "semantic_claim_size",
        "semantic_claimed",
        "smc",
        "started_utc",
        "stophud",
        "target",
        "temporary_sysctl_write",
        "temporary_sysctl_write_attempted",
        "transport_module",
        "transport_source",
        "transport_source_sha256",
        "transport_source_size",
        "transport_source_verified",
        "value",
    }
)

_JOURNAL_KEYS = frozenset(
    {
        "automatic_retries",
        "boot_id_before_read",
        "boot_id_before_read_sha256",
        "candidate_sha256",
        "candidate_size",
        "cleanup_ok",
        "completed_utc",
        "control_manifest",
        "current_boot_attestation",
        "device_state_write",
        "dispatch_count",
        "dispatch_failed",
        "dispatch_returned",
        "effect_ambiguous",
        "effect_dispatched",
        "effect_replayed",
        "error",
        "experiment_id",
        "failed_stage",
        "fixed_op",
        "fixed_op_measurement",
        "flash_completed_utc",
        "flash_image_sha256",
        "flash_journal",
        "flash_journal_bound",
        "flash_journal_sha256",
        "flash_journal_size",
        "flash_predecessor_sha256",
        "flash_profile",
        "flash_readback_sha256",
        "frames",
        "health_after",
        "memory_or_mmio_writes",
        "mode",
        "op",
        "op_args",
        "outcome",
        "panic_on_oops_before",
        "panic_on_oops_restored",
        "panic_on_oops_zero_set",
        "panic_on_oops_zero_verified",
        "panic_restore_deferred",
        "panic_transition",
        "promotion",
        "reboot_dispatched",
        "replay_safe",
        "schema",
        "semantic_claim_key_sha256",
        "semantic_claim_path",
        "semantic_claim_sha256",
        "semantic_claim_size",
        "semantic_claimed",
        "started_utc",
        "status",
        "stophud",
        "stophud_accepted",
        "stophud_attempts",
        "target_verified",
        "temporary_sysctl_write",
        "temporary_sysctl_write_attempted",
        "transport_module",
        "transport_source",
        "transport_source_sha256",
        "transport_source_size",
        "transport_source_verified",
        "value",
    }
)

_BRIDGE_KEYS = frozenset(
    {
        "bridge_process_script",
        "bridge_process_script_descriptor",
        "bridge_process_script_path",
        "listener",
        "process_argv",
        "process_pid",
        "serial_device",
        "serial_identity",
        "serial_realpath",
        "serial_stat",
        "unique_process",
        "validated_utc",
    }
)

def _validate_bridge_binding(value: object) -> dict[str, object]:
    """Validate private bridge shape without treating it as authority.

    The old bridge receipt is retained input, not a new authority source.  Its
    private paths, serial values and process identity are intentionally not
    copied into the public capsule.  The exact old byte pin still binds the
    retained record; this function only rejects type/key-set confusion in a
    fixture that has been re-pinned by a test seam.
    """
    bridge = _require_exact_keys(value, _BRIDGE_KEYS, "raw.bridge_binding")
    if type(bridge["bridge_process_script"]) is not str:
        raise ControlRetryError("raw.bridge_binding script is not text")
    descriptor = _require_exact_keys(
        bridge["bridge_process_script_descriptor"],
        frozenset({"basename", "sha256", "size_bytes"}),
        "raw.bridge_binding descriptor",
    )
    if (
        type(descriptor["basename"]) is not str
        or not descriptor["basename"]
        or _sha256_text(descriptor["sha256"], "raw.bridge_binding descriptor")
        != descriptor["sha256"]
        or type(descriptor["size_bytes"]) is not int
        or descriptor["size_bytes"] <= 0
    ):
        raise ControlRetryError("raw.bridge_binding descriptor is malformed")
    if type(bridge["bridge_process_script_path"]) is not str:
        raise ControlRetryError("raw.bridge_binding script path is not text")
    listener = _require_exact_keys(
        bridge["listener"], frozenset({"host", "port"}), "raw.bridge_binding listener"
    )
    if type(listener["host"]) is not str or type(listener["port"]) is not int:
        raise ControlRetryError("raw.bridge_binding listener is malformed")
    process_argv = bridge["process_argv"]
    if (
        type(process_argv) is not list
        or not process_argv
        or any(type(item) is not str for item in process_argv)
    ):
        raise ControlRetryError("raw.bridge_binding process argv is malformed")
    if type(bridge["process_pid"]) is not int or bridge["process_pid"] <= 0:
        raise ControlRetryError("raw.bridge_binding process pid is malformed")
    for key in ("serial_device", "serial_identity", "serial_realpath", "validated_utc"):
        if type(bridge[key]) is not str or not bridge[key]:
            raise ControlRetryError(f"raw.bridge_binding {key} is malformed")
    serial_stat = _require_exact_keys(
        bridge["serial_stat"],
        frozenset({"character_device", "mode", "st_dev", "st_ino", "st_rdev"}),
        "raw.bridge_binding serial stat",
    )
    if (
        type(serial_stat["character_device"]) is not bool
        or type(serial_stat["mode"]) is not int
        or type(serial_stat["st_dev"]) is not int
        or type(serial_stat["st_ino"]) is not int
        or type(serial_stat["st_rdev"]) is not int
        or any(serial_stat[key] < 0 for key in ("mode", "st_dev", "st_ino", "st_rdev"))
    ):
        raise ControlRetryError("raw.bridge_binding serial stat is malformed")
    _require_true(bridge, "unique_process", "raw.bridge_binding")
    return bridge


def _validate_public_record(
    public: object,
    artifacts: Mapping[str, object],
) -> dict[str, object]:
    """Apply the exact public projection contract for the old incident."""

    record = _require_exact_keys(public, _PUBLIC_KEYS, "public predecessor")
    scalar_values: dict[str, object] = {
        "schema": "sdm855-a90-inline-remapper-mid-public-v1",
        "experiment_id": PREDECESSOR_ID,
        "mode": "control",
        "started_utc": INCIDENT_STARTED_UTC,
        "completed_utc": INCIDENT_COMPLETED_UTC,
        "boot_id_before_read_sha256": None,
        "arbitrary_address_input": False,
        "automatic_retries": False,
        "candidate_sha256": CANDIDATE_SHA256,
        "candidate_size": CANDIDATE_SIZE_BYTES,
        "claim_boundary": "The incident does not establish MMIO reachability or refusal.",
        "clean_negative": False,
        "cleanup_ok": False,
        "bridge_bound": True,
        "control_manifest": None,
        "controller_writes": False,
        "current_boot_attestation": None,
        "dispatch_count": 0,
        "dispatch_failed": False,
        "dispatch_returned": False,
        "effect_ambiguous": False,
        "effect_dispatched": False,
        "effect_replayed": False,
        "device_state_write": False,
        "failed_stage": "preflight",
        "final_bridge_bound": False,
        "flash_completed_utc": FLASH_COMPLETED_UTC,
        "flash_image_sha256": CANDIDATE_SHA256,
        "flash_journal_bound": True,
        "flash_journal_sha256": FLASH_JOURNAL_SHA256,
        "flash_journal_size": FLASH_JOURNAL_SIZE,
        "flash_predecessor_sha256": FLASH_PREDECESSOR_SHA256,
        "flash_profile": "control",
        "flash_readback_sha256": CANDIDATE_SHA256,
        "generic_call_target": False,
        "health_after_ok": False,
        "memory_or_mmio_writes": False,
        "op": FIXED_OP,
        "op_args": [],
        "outcome": "INCIDENT",
        "panic_on_oops_before": None,
        "panic_on_oops_restored": False,
        "panic_on_oops_zero_set": False,
        "panic_on_oops_zero_verified": False,
        "panic_restore_deferred": False,
        "partial_transport_retained_private": True,
        "partition_writes": False,
        "promotion": "INCIDENT_RECONCILE_REQUIRED",
        "protected_memory_read": False,
        "raw_cmdline_omitted": True,
        "raw_snapshot_size": RAW_SIZE_BYTES,
        "raw_value_omitted": True,
        "reboot_dispatched": False,
        "requires_last_kmsg_rollback_health": False,
        "returned_value_present": False,
        "returned_value_sha256": None,
        "runtime": None,
        "security_classification": "NOT_TRIGGERED",
        "semantic_claim": None,
        "serial_identity_omitted": True,
        "smc": False,
        "soc": None,
        "stophud_accepted": False,
        "stophud_busy_retries": 0,
        "target_evaluation": "NOT_EVALUATED",
        "target_model": None,
        "target_verified": False,
        "temporary_sysctl_write": False,
        "temporary_sysctl_write_attempted": False,
        "transport_module": TRANSPORT_MODULE,
        "transport_no_value": False,
        "transport_source": TRANSPORT_SOURCE,
        "transport_source_sha256": TRANSPORT_SOURCE_SHA256,
        "transport_source_size": TRANSPORT_SOURCE_SIZE,
        "transport_source_verified": True,
        "journal_size": JOURNAL_SIZE_BYTES,
    }
    for key, expected in scalar_values.items():
        _require_value(record, key, expected, "public predecessor")

    fixed = _require_exact_keys(
        record.get("fixed_op"),
        frozenset({"args", "buffer_sha256", "buffer_size", "op", "rc", "status", "value"}),
        "public predecessor.fixed_op",
    )
    for key, expected in {
        "args": [],
        "buffer_sha256": FIXED_OP_BUFFER_SHA256,
        "buffer_size": FIXED_OP_BUFFER_SIZE,
        "op": FIXED_OP,
        "rc": None,
        "status": None,
        "value": None,
    }.items():
        _require_value(fixed, key, expected, "public predecessor.fixed_op")

    _require_panic_transition(record.get("panic_transition"), "public predecessor.panic_transition")
    private_record = _require_exact_keys(
        record.get("private_record"),
        frozenset({"filename", "git_ignored", "journal_filename"}),
        "public predecessor.private_record",
    )
    for key, expected in {
        "filename": "verification-024-control.json",
        "git_ignored": True,
        "journal_filename": "verification-024-control.journal.json",
    }.items():
        _require_value(private_record, key, expected, "public predecessor.private_record")

    public_artifacts = {
        "raw": {
            "sha256": record["raw_snapshot_sha256"],
            "size_bytes": record["raw_snapshot_size"],
        },
        "journal": {
            "sha256": record["journal_sha256"],
            "size_bytes": record["journal_size"],
        },
    }
    for role in ("raw", "journal"):
        descriptor = _require_artifact_descriptor(artifacts.get(role), role)
        if (
            public_artifacts[role]["sha256"] != descriptor["sha256"]
            or public_artifacts[role]["size_bytes"] != descriptor["size_bytes"]
        ):
            raise ControlRetryError(f"public predecessor {role} hash/size binding differs")
    public_descriptor = _require_artifact_descriptor(artifacts.get("public"), "public")
    if (
        record["raw_snapshot_sha256"] != RAW_SHA256
        or record["raw_snapshot_size"] != RAW_SIZE_BYTES
        or record["journal_sha256"] != JOURNAL_SHA256
        or record["journal_size"] != JOURNAL_SIZE_BYTES
        or public_descriptor["sha256"] != PUBLIC_SHA256
        or public_descriptor["size_bytes"] != PUBLIC_SIZE_BYTES
    ):
        raise ControlRetryError("public predecessor artifact pins are not exact")
    return record


def _reject_a90r_tokens(value: object, label: str) -> None:
    """Reject a returned-value marker anywhere in the predecessor input."""

    if isinstance(value, str):
        if "A90R" in value:
            raise ControlRetryError(f"{label} contains an unexpected A90R record")
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            _reject_a90r_tokens(key, label)
            _reject_a90r_tokens(nested, label)
    elif isinstance(value, list):
        for nested in value:
            _reject_a90r_tokens(nested, label)


def _validate_raw_record(raw: object) -> dict[str, object]:
    """Validate every private raw field that can affect the retry decision."""

    record = _require_exact_keys(raw, _RAW_KEYS, "raw predecessor")
    scalar_values: dict[str, object] = {
        "schema": "sdm855-a90-inline-remapper-mid-private-v1",
        "experiment_id": PREDECESSOR_ID,
        "mode": "control",
        "started_utc": INCIDENT_STARTED_UTC,
        "completed_utc": INCIDENT_COMPLETED_UTC,
        "boot_id_before_read": None,
        "boot_id_before_read_sha256": None,
        "candidate_sha256": CANDIDATE_SHA256,
        "candidate_size": CANDIDATE_SIZE_BYTES,
        "cleanup_ok": False,
        "control_manifest": None,
        "controller_writes": False,
        "current_boot_attestation": None,
        "device_state_write": False,
        "dispatch_count": 0,
        "dispatch_failed": False,
        "dispatch_returned": False,
        "effect_ambiguous": False,
        "effect_dispatched": False,
        "effect_replayed": False,
        "failed_stage": "preflight",
        "final_bridge_bound": False,
        "fixed_op_measurement": None,
        "memory_or_mmio_writes": False,
        "op": FIXED_OP,
        "op_args": [],
        "outcome": "INCIDENT",
        "panic_on_oops_before": None,
        "panic_on_oops_restored": False,
        "panic_on_oops_zero_set": False,
        "panic_on_oops_zero_verified": False,
        "panic_restore_deferred": False,
        "partition_writes": False,
        "promotion": "INCIDENT_RECONCILE_REQUIRED",
        "protected_memory_read": False,
        "reboot_dispatched": False,
        "security_classification": "NOT_TRIGGERED",
        "semantic_claim_key_sha256": None,
        "semantic_claim_path": None,
        "semantic_claim_sha256": None,
        "semantic_claim_size": None,
        "semantic_claimed": False,
        "smc": False,
        "stophud": None,
        "target": None,
        "temporary_sysctl_write": False,
        "temporary_sysctl_write_attempted": False,
        "transport_module": TRANSPORT_MODULE,
        "transport_source": TRANSPORT_SOURCE,
        "transport_source_sha256": TRANSPORT_SOURCE_SHA256,
        "transport_source_size": TRANSPORT_SOURCE_SIZE,
        "transport_source_verified": True,
        "value": None,
    }
    for key, expected in scalar_values.items():
        _require_value(record, key, expected, "raw predecessor")
    _validate_bridge_binding(record.get("bridge_binding"))
    _require_health(record.get("health_after"), "raw predecessor.health_after")
    _require_error(record.get("error"), "raw predecessor.error")
    _require_panic_transition(record.get("panic_transition"), "raw predecessor.panic_transition")
    _require_flash_journal(record.get("flash_journal"), "raw predecessor.flash_journal")

    frames = record.get("frames")
    if type(frames) is not list or len(frames) != 1:
        raise ControlRetryError("raw predecessor frame list is not exactly one legacy record")
    _require_legacy_frame(frames[0], "raw predecessor.frames[0]")
    return record


def _validate_journal_record(journal: object) -> dict[str, object]:
    """Validate the durable journal projection of the old pre-dispatch incident."""

    record = _require_exact_keys(journal, _JOURNAL_KEYS, "journal predecessor")
    scalar_values: dict[str, object] = {
        "schema": "sdm855-a90-inline-remapper-mid-journal-v1",
        "experiment_id": PREDECESSOR_ID,
        "mode": "control",
        "status": "REFUSED_PRE_DISPATCH",
        "started_utc": INCIDENT_STARTED_UTC,
        "completed_utc": INCIDENT_COMPLETED_UTC,
        "boot_id_before_read": None,
        "boot_id_before_read_sha256": None,
        "candidate_sha256": CANDIDATE_SHA256,
        "candidate_size": CANDIDATE_SIZE_BYTES,
        "cleanup_ok": False,
        "control_manifest": None,
        "current_boot_attestation": None,
        "device_state_write": False,
        "dispatch_count": 0,
        "dispatch_failed": False,
        "dispatch_returned": False,
        "effect_ambiguous": False,
        "effect_dispatched": False,
        "effect_replayed": False,
        "failed_stage": "preflight",
        "fixed_op_measurement": None,
        "flash_completed_utc": FLASH_COMPLETED_UTC,
        "flash_image_sha256": CANDIDATE_SHA256,
        "flash_journal_bound": True,
        "flash_journal_sha256": FLASH_JOURNAL_SHA256,
        "flash_journal_size": FLASH_JOURNAL_SIZE,
        "flash_predecessor_sha256": FLASH_PREDECESSOR_SHA256,
        "flash_profile": "control",
        "flash_readback_sha256": CANDIDATE_SHA256,
        "memory_or_mmio_writes": False,
        "op": FIXED_OP,
        "op_args": [],
        "outcome": "INCIDENT",
        "panic_on_oops_before": None,
        "panic_on_oops_restored": False,
        "panic_on_oops_zero_set": False,
        "panic_on_oops_zero_verified": False,
        "panic_restore_deferred": False,
        "promotion": "INCIDENT_RECONCILE_REQUIRED",
        "reboot_dispatched": False,
        "replay_safe": False,
        "semantic_claim_key_sha256": None,
        "semantic_claim_path": None,
        "semantic_claim_sha256": None,
        "semantic_claim_size": None,
        "semantic_claimed": False,
        "target_verified": False,
        "temporary_sysctl_write": False,
        "temporary_sysctl_write_attempted": False,
        "transport_module": TRANSPORT_MODULE,
        "transport_source": TRANSPORT_SOURCE,
        "transport_source_sha256": TRANSPORT_SOURCE_SHA256,
        "transport_source_size": TRANSPORT_SOURCE_SIZE,
        "transport_source_verified": True,
        "value": None,
    }
    for key, expected in scalar_values.items():
        _require_value(record, key, expected, "journal predecessor")
    _require_health(record.get("health_after"), "journal predecessor.health_after")
    _require_error(record.get("error"), "journal predecessor.error")
    _require_panic_transition(record.get("panic_transition"), "journal predecessor.panic_transition")
    _require_flash_journal(record.get("flash_journal"), "journal predecessor.flash_journal")

    fixed = _require_exact_keys(
        record.get("fixed_op"),
        frozenset({"args", "buffer_sha256", "buffer_size", "op"}),
        "journal predecessor.fixed_op",
    )
    for key, expected in {
        "args": [],
        "buffer_sha256": FIXED_OP_BUFFER_SHA256,
        "buffer_size": FIXED_OP_BUFFER_SIZE,
        "op": FIXED_OP,
    }.items():
        _require_value(fixed, key, expected, "journal predecessor.fixed_op")

    frames = record.get("frames")
    if type(frames) is not list or len(frames) != 1:
        raise ControlRetryError("journal predecessor frame list is not exactly one legacy record")
    _require_legacy_frame(frames[0], "journal predecessor.frames[0]")
    attempts = record.get("stophud_attempts")
    if type(attempts) is not list or len(attempts) != 1:
        raise ControlRetryError("journal predecessor stophud attempts are not exact")
    _require_legacy_frame(attempts[0], "journal predecessor.stophud_attempts[0]")
    if attempts != frames:
        raise ControlRetryError("journal predecessor stophud attempts differ from frames")
    _require_value(record, "stophud", None, "journal predecessor")
    _require_false(record, "stophud_accepted", "journal predecessor")
    return record


def _validate_cross_bindings(
    public: Mapping[str, object],
    raw: Mapping[str, object],
    journal: Mapping[str, object],
    artifacts: Mapping[str, object],
) -> None:
    """Require all three projections to describe the same old incident."""

    if raw.get("frames") != journal.get("frames"):
        raise ControlRetryError("raw/journal legacy frame records differ")
    if raw.get("error") != journal.get("error"):
        raise ControlRetryError("raw/journal error records differ")
    if raw.get("health_after") != journal.get("health_after"):
        raise ControlRetryError("raw/journal health projections differ")
    if raw.get("flash_journal") != journal.get("flash_journal"):
        raise ControlRetryError("raw/journal flash projections differ")
    if raw.get("panic_transition") != journal.get("panic_transition"):
        raise ControlRetryError("raw/journal panic projections differ")

    common_keys = (
        "automatic_retries",
        "candidate_sha256",
        "candidate_size",
        "cleanup_ok",
        "completed_utc",
        "control_manifest",
        "current_boot_attestation",
        "device_state_write",
        "dispatch_count",
        "dispatch_failed",
        "dispatch_returned",
        "effect_ambiguous",
        "effect_dispatched",
        "effect_replayed",
        "experiment_id",
        "failed_stage",
        "memory_or_mmio_writes",
        "mode",
        "op",
        "op_args",
        "outcome",
        "panic_on_oops_before",
        "panic_on_oops_restored",
        "panic_on_oops_zero_set",
        "panic_on_oops_zero_verified",
        "panic_restore_deferred",
        "promotion",
        "reboot_dispatched",
        "semantic_claim_key_sha256",
        "semantic_claim_path",
        "semantic_claim_sha256",
        "semantic_claim_size",
        "semantic_claimed",
        "started_utc",
        "temporary_sysctl_write",
        "temporary_sysctl_write_attempted",
        "transport_module",
        "transport_source",
        "transport_source_sha256",
        "transport_source_size",
        "transport_source_verified",
        "value",
    )
    for key in common_keys:
        if raw.get(key) != journal.get(key):
            raise ControlRetryError(f"raw/journal field {key!r} differs")

    for key in (
        "candidate_sha256",
        "candidate_size",
        "completed_utc",
        "cleanup_ok",
        "dispatch_count",
        "dispatch_failed",
        "dispatch_returned",
        "effect_ambiguous",
        "effect_dispatched",
        "effect_replayed",
        "flash_image_sha256",
        "flash_journal_bound",
        "flash_journal_sha256",
        "flash_journal_size",
        "flash_predecessor_sha256",
        "flash_profile",
        "flash_readback_sha256",
        "memory_or_mmio_writes",
        "op",
        "outcome",
        "panic_on_oops_before",
        "panic_on_oops_restored",
        "panic_on_oops_zero_set",
        "panic_on_oops_zero_verified",
        "panic_restore_deferred",
        "partition_writes",
        "promotion",
        "reboot_dispatched",
        "started_utc",
        "temporary_sysctl_write",
        "temporary_sysctl_write_attempted",
        "transport_module",
        "transport_source",
        "transport_source_sha256",
        "transport_source_size",
        "transport_source_verified",
    ):
        if public.get(key) != journal.get(key) and key != "partition_writes":
            raise ControlRetryError(f"public/journal field {key!r} differs")
    if public.get("partition_writes") is not False or raw.get("partition_writes") is not False:
        raise ControlRetryError("partition write projection is not false")

    expected_raw = _require_artifact_descriptor(artifacts.get("raw"), "raw")
    expected_journal = _require_artifact_descriptor(artifacts.get("journal"), "journal")
    expected_public = _require_artifact_descriptor(artifacts.get("public"), "public")
    if expected_raw["sha256"] != RAW_SHA256 or expected_raw["size_bytes"] != RAW_SIZE_BYTES:
        raise ControlRetryError("raw artifact pin differs")
    if expected_journal["sha256"] != JOURNAL_SHA256 or expected_journal["size_bytes"] != JOURNAL_SIZE_BYTES:
        raise ControlRetryError("journal artifact pin differs")
    if expected_public["sha256"] != PUBLIC_SHA256 or expected_public["size_bytes"] != PUBLIC_SIZE_BYTES:
        raise ControlRetryError("public artifact pin differs")


def _public_capsule_artifacts(artifacts: Mapping[str, object]) -> dict[str, object]:
    """Return only safe basename/hash/size records for public publication."""

    return {
        role: _require_artifact_descriptor(artifacts.get(role), role)
        for role in ("public", "raw", "journal")
    }


def _build_capsule_body(
    public: Mapping[str, object],
    raw: Mapping[str, object],
    journal: Mapping[str, object],
    artifacts: Mapping[str, object],
) -> dict[str, object]:
    """Build the deterministic, redacted A2a predecessor capsule."""

    del public, raw, journal
    source_pins = {
        name: {
            "basename": str(pin["basename"]),
            "size_bytes": int(pin["size_bytes"]),
            "sha256": str(pin["sha256"]),
            "pin_kind": "historical_source_bytes",
        }
        for name, pin in PRODUCER_SOURCE_PINS.items()
    }
    provenance = {
        "scope": "historical_incident_predecessor_only; current_r2_pins_are_A3_journal_scope",
        "historical_producer_commit": PRODUCER_COMMIT,
        "historical_source_byte_pins": source_pins,
    }
    semantic = {
        "identity": {
            "predecessor_id": PREDECESSOR_ID,
            "active_control_id": ACTIVE_CONTROL_ID,
            "mode": "control",
            "started_utc": INCIDENT_STARTED_UTC,
            "completed_utc": INCIDENT_COMPLETED_UTC,
            "old_id_role": "predecessor_only",
        },
        "candidate": {
            "sha256": CANDIDATE_SHA256,
            "size_bytes": CANDIDATE_SIZE_BYTES,
        },
        "fixed_op": {
            "op": FIXED_OP,
            "args": [],
            "buffer_size": FIXED_OP_BUFFER_SIZE,
            "buffer_sha256": FIXED_OP_BUFFER_SHA256,
            "dispatch_count": 0,
            "dispatched": False,
            "returned": False,
            "value": None,
        },
        "flash": {
            "profile": "control",
            "sha256": FLASH_JOURNAL_SHA256,
            "size_bytes": FLASH_JOURNAL_SIZE,
            "image_sha256": CANDIDATE_SHA256,
            "readback_sha256": CANDIDATE_SHA256,
            "predecessor_sha256": FLASH_PREDECESSOR_SHA256,
            "completed_utc": FLASH_COMPLETED_UTC,
        },
        "transport": {
            "module": TRANSPORT_MODULE,
            "source_basename": Path(TRANSPORT_SOURCE).name,
            "sha256": TRANSPORT_SOURCE_SHA256,
            "size_bytes": TRANSPORT_SOURCE_SIZE,
            "incident_recorded_source_verified": True,
        },
        "failure": {
            "outcome": "INCIDENT",
            "promotion": "INCIDENT_RECONCILE_REQUIRED",
            "journal_status": "REFUSED_PRE_DISPATCH",
            "failed_stage": "preflight",
            "security_classification": "NOT_TRIGGERED",
        },
        "legacy_frame": {
            "evidence_id": "stophud_1",
            "argv": ["stophud"],
            "attempt": 1,
            "transport_error_type": "ProbeError",
            "recorded_failure": "STOPHUD_SUCCESS_PAYLOAD_NONEMPTY",
            "complete_frame": False,
            "partial": None,
            "lost_frame_reconstructed": False,
        },
        "health": {"ok": False, "reason": "target_not_bound", "skipped": True},
        "hud": {
            "state": "UNKNOWN_IDEMPOTENT",
            "accepted": False,
            "busy_retries": 0,
        },
        "effect": {
            "dispatch_count": 0,
            "dispatch_returned": False,
            "dispatch_failed": False,
            "effect_dispatched": False,
            "effect_ambiguous": False,
            "effect_replayed": False,
            "panic_transition_started": False,
            "partition_writes": False,
            "memory_or_mmio_writes": False,
        },
    }
    claims = {
        "effect_grades": {
            "fixed_op": "PROVED_ZERO",
            "panic": "PROVED_ZERO",
            "partition": "PROVED_ZERO",
            "controller": "PROVED_ZERO",
            "device_state": "PROVED_ZERO",
        },
        "mmio_effect": "PROVED_ZERO",
        "stophud_state_change": "UNKNOWN_IDEMPOTENT",
        "partial_transport_retained_private_is_authority": False,
        "historical_bridge_is_authority": False,
        "live_authority": False,
        "replay_allowed": False,
        "old_id_reuse_allowed": False,
        "fallback_allowed": False,
        "legacy_marker": {
            "partial_transport_retained_private": True,
            "authority": False,
        },
    }
    body = {
        "schema": CAPSULE_SCHEMA,
        "phase": CAPSULE_PHASE,
        "predecessor_id": PREDECESSOR_ID,
        "active_control_id": ACTIVE_CONTROL_ID,
        "provenance": provenance,
        "artifacts": _public_capsule_artifacts(artifacts),
        "semantic": semantic,
        "claims": claims,
    }
    if set(body) != set(_CAPSULE_TOP_KEYS):
        raise ControlRetryError("capsule top-level schema drifted")
    if set(semantic) != set(_CAPSULE_SEMANTIC_KEYS):
        raise ControlRetryError("capsule semantic schema drifted")
    if set(claims) != set(_CAPSULE_CLAIM_KEYS):
        raise ControlRetryError("capsule claims schema drifted")
    return body


def _validate_capsule_public_safety(capsule: Mapping[str, object]) -> None:
    """Ensure the A2a result cannot expose private paths or wire payloads."""

    def walk(value: object) -> None:
        if isinstance(value, str):
            if value.startswith("/") or "/home/" in value or "/dev/tty" in value:
                raise ControlRetryError("capsule contains a private absolute path")
            if value in {"serial", "serial_device", "serial_identity"}:
                raise ControlRetryError("capsule contains private serial data")
            return
        if isinstance(value, dict):
            for key, nested in value.items():
                if key in {
                    "bridge_binding",
                    "process_argv",
                    "process_pid",
                    "listener",
                    "error",
                    "payload_base64",
                    "transcript_base64",
                }:
                    raise ControlRetryError("capsule contains private evidence fields")
                walk(key)
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(dict(capsule))


def _validate_predecessor_semantics(triplet: Mapping[str, object]) -> dict[str, object]:
    """Validate the A1 private triplet and return a redacted A2a capsule.

    This is a pure function over the already descriptor-bound A1 result.  It
    performs no filesystem reads, subprocess calls, Git inspection, device
    contact or writes.  Its output contains only fixed semantic facts and
    public-safe artifact descriptors; the private parsed records are never
    copied into the returned capsule.
    """

    if type(triplet) is not dict:
        raise ControlRetryError("predecessor triplet is not an object")
    expected_triplet_keys = frozenset(
        {"predecessor_id", "active_control_id", "public", "raw", "journal", "artifacts"}
    )
    if set(triplet) != set(expected_triplet_keys):
        raise ControlRetryError("predecessor triplet fields are not exact")
    _require_value(triplet, "predecessor_id", PREDECESSOR_ID, "predecessor triplet")
    _require_value(triplet, "active_control_id", ACTIVE_CONTROL_ID, "predecessor triplet")

    artifacts = _require_exact_keys(
        triplet.get("artifacts"), frozenset({"public", "raw", "journal"}), "triplet.artifacts"
    )
    for role in ("public", "raw", "journal"):
        _require_artifact_descriptor(artifacts.get(role), role)

    public = _validate_public_record(triplet.get("public"), artifacts)
    raw = _validate_raw_record(triplet.get("raw"))
    journal = _validate_journal_record(triplet.get("journal"))
    _reject_a90r_tokens(triplet, "predecessor triplet")
    _validate_cross_bindings(public, raw, journal, artifacts)
    capsule = _build_capsule_body(public, raw, journal, artifacts)
    _validate_capsule_public_safety(capsule)
    return capsule


def _canonical_capsule_descriptor(capsule: Mapping[str, object]) -> dict[str, object]:
    """Private spelling retained for A2 review harnesses."""

    data = canonical_capsule_bytes(dict(capsule))
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}


__all__ = [
    "ACTIVE_CONTROL_ID",
    "ControlRetryError",
    "FIXED_RELATIVE_PATHS",
    "JOURNAL_MODE",
    "JOURNAL_PIN",
    "JOURNAL_RELATIVE_PATH",
    "JOURNAL_SHA256",
    "JOURNAL_SIZE",
    "JOURNAL_SIZE_BYTES",
    "MAX_ARTIFACT_BYTES",
    "MAX_FILE_BYTES",
    "MAX_RECEIPT_BYTES",
    "PINS",
    "PREDECESSOR_ID",
    "PREDECESSOR_JOURNAL_PATH",
    "PREDECESSOR_JOURNAL_RELATIVE_PATH",
    "PREDECESSOR_PINS",
    "PREDECESSOR_PUBLIC_PATH",
    "PREDECESSOR_PUBLIC_RELATIVE_PATH",
    "PREDECESSOR_RAW_PATH",
    "PREDECESSOR_RAW_RELATIVE_PATH",
    "PUBLIC_MODE",
    "PUBLIC_PIN",
    "PUBLIC_RELATIVE_PATH",
    "PUBLIC_SHA256",
    "PUBLIC_SIZE",
    "PUBLIC_SIZE_BYTES",
    "RAW_MODE",
    "RAW_PIN",
    "RAW_RELATIVE_PATH",
    "RAW_SHA256",
    "RAW_SIZE",
    "RAW_SIZE_BYTES",
    "REPO_ROOT",
    "RetryInputError",
    "TRIPLET_PINS",
    "TripletReadError",
    "read_triplet",
    "stable_read_triplet",
]
