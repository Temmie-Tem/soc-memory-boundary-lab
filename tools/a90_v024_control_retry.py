#!/usr/bin/env python3
"""Read the pinned Verification 024 control predecessor for R2.

Phase R2-A1 is deliberately a host-only input boundary.  It resolves one
pre-registered public/private triplet, reads each inode through a no-follow
descriptor, and applies only byte-level integrity checks.  The parsed JSON is
returned as PRIVATE IN-MEMORY input for the later A2 phase: raw/journal values
must not be published or logged, and this return is not a public capsule.
This module intentionally does not decide whether any field has the expected
semantic value and it never contacts a device or a transport.
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
