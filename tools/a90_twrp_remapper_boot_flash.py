#!/usr/bin/env python3
"""Flash one exact Verification 024 remapper candidate through A90 TWRP.

This is a deliberately small, flash-only transaction owner.  It accepts only
the three pre-registered profiles and the fixed predecessor graph::

    V2321 rollback -> control -> read -> V2321 rollback

The input is checked against a complete 60,882,944-byte image and a pinned
SHA-256 before the first ADB command.  The exact SM-A908N/r3q TWRP endpoint,
the TWRP version, and the ``boot`` alias resolution are then checked before a
single bounded ``dd`` write.  Remote staging and complete boot-prefix
readback are verified, staging is removed and its absence proved, and no
reboot/recovery command is ever issued here.

The module is import-safe.  Tests replace ``run_checked`` and
``select_exact_recovery`` with mocked transport; importing it never invokes
ADB or discovers a device.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Callable, Mapping, Sequence


def _upstream_root() -> Path:
    """Root of the upstream android-native-init-lab checkout.

    Override with ANDROID_NATIVE_INIT_LAB when it is not at the default path.
    """
    return Path(
        os.environ.get(
            "ANDROID_NATIVE_INIT_LAB",
            Path.home() / "dev" / "android-native-init-lab",
        )
    )


try:
    from tools.a90_acm_snapshot import json_bytes
    from tools.a90_twrp_system_boot import (
        TARGET_DEVICE,
        TARGET_MODEL,
        TARGET_SERIAL_SHA256,
        TWRP_VERSION,
        AdbEndpoint,
        parse_adb_devices,
        select_exact_recovery,
    )
    from tools.a90_v024_physical_claim import (
        PhysicalClaimAlreadyExists,
        PhysicalClaimError,
        boot_prefix_claim_identity,
        boot_prefix_claim_path,
        claim_boot_prefix,
    )
    from tools import build_a90_inline_remapper_candidate as candidate
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes  # type: ignore
    from a90_twrp_system_boot import (  # type: ignore
        TARGET_DEVICE,
        TARGET_MODEL,
        TARGET_SERIAL_SHA256,
        TWRP_VERSION,
        AdbEndpoint,
        parse_adb_devices,
        select_exact_recovery,
    )
    from a90_v024_physical_claim import (  # type: ignore
        PhysicalClaimAlreadyExists,
        PhysicalClaimError,
        boot_prefix_claim_identity,
        boot_prefix_claim_path,
        claim_boot_prefix,
    )
    import build_a90_inline_remapper_candidate as candidate  # type: ignore


BOOT_PREFIX_SIZE = 60_882_944
BOOT_BLOCK_ALIAS = "/dev/block/by-name/boot"
BOOT_BLOCK_RESOLVED = "/dev/block/sda24"
REMOTE_STAGING = "/tmp/sdm855-remapper-boot.img"
REMOTE_STAGING_BY_PROFILE = {
    # Keep the historical control spelling as its fixed, profile-owned path;
    # read and rollback are deliberately distinct paths.
    "control": REMOTE_STAGING,
    "read": "/tmp/sdm855-remapper-boot-read.img",
    "rollback": "/tmp/sdm855-remapper-boot-rollback.img",
}
DD_BLOCK_SIZE = 4096
DD_BLOCK_COUNT = BOOT_PREFIX_SIZE // DD_BLOCK_SIZE
SUBPROCESS_TIMEOUT_SEC = 300.0
GUARDED_EFFECT_SCHEMA = "sdm855-a90-remapper-guarded-effect-v1"

# The flash journal is an owner identity, not an operator-selected output.
# Tests may replace this constant with an isolated temporary repository, but
# production callers cannot redirect it through Namespace attributes or CLI
# options.
REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = REPO_ROOT
# The transport executable is part of the owner identity.  Pin an absolute
# regular-file path so a caller's PATH cannot shadow the stateful transport.
# Tests replace ``run_checked`` and never invoke this binary.
ADB = "/usr/lib/android-sdk/platform-tools/adb"

CONTROL_SHA256 = (
    "dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247"
)
READ_SHA256 = (
    "6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed"
)
ROLLBACK_SHA256 = (
    "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb"
)

# Aliases retained for callers familiar with the older SHRM flash helper.
CONTROL_HASH = CONTROL_SHA256
READ_HASH = READ_SHA256
ROLLBACK_HASH = ROLLBACK_SHA256
CONTROL_SHA = CONTROL_SHA256
READ_SHA = READ_SHA256
ROLLBACK_SHA = ROLLBACK_SHA256

PROFILES = (candidate.MODE_CONTROL, candidate.MODE_READ, "rollback")
PASS_READBACK_AND_CLEANUP = "PASS_READBACK_AND_CLEANUP"
ALLOWED_PREDECESSORS: Mapping[str, frozenset[str]] = {
    # The read candidate is never allowed to be booted directly from stock;
    # the no-load control is the state-equivalent predecessor.
    candidate.MODE_CONTROL: frozenset({ROLLBACK_SHA256}),
    candidate.MODE_READ: frozenset({CONTROL_SHA256}),
    "rollback": frozenset({CONTROL_SHA256, READ_SHA256}),
}
PROFILE_PREDECESSORS = ALLOWED_PREDECESSORS

DEFAULT_CANDIDATES = {
    candidate.MODE_CONTROL: Path(
        "evidence/private/verification-024-remapper-build-20260827-01/"
        "control/boot_linux_inline_remapper_control_v1.img"
    ),
    candidate.MODE_READ: Path(
        "evidence/private/verification-024-remapper-build-20260827-01/"
        "read/boot_linux_inline_remapper_read_v1.img"
    ),
}

DEFAULT_ROLLBACK = (
    _upstream_root()
    / "workspace/private/inputs/boot_images"
    / "boot_linux_v2321_usb_clean_identity_rodata.img"
)

HASH_RE = re.compile(r"(?m)^([0-9a-f]{64})(?:\s|$)")
DECIMAL_RE = re.compile(r"[0-9]+\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
Runner = Callable[[Sequence[str]], str]


class FlashError(RuntimeError):
    """A failure of the exact TWRP flash transaction contract."""


def sha256_file(path: Path) -> str:
    """Hash one regular local file without accepting a symlink alias."""

    return _stable_file_digest(path)[1]


def _reject_symlink_components(path: Path, label: str = "image") -> None:
    """Reject a leaf or parent symlink before opening a candidate image."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    if path.is_symlink():
        raise FlashError(f"{label} must not be a symlink: {path}")
    cursor = lexical.parent
    anchor = Path(cursor.anchor or "/")
    while True:
        if cursor.is_symlink():
            raise FlashError(f"{label} parent component must not be a symlink: {cursor}")
        if cursor == anchor:
            break
        cursor = cursor.parent


def _stable_file_digest(path: Path) -> tuple[int, str]:
    """Read one regular image through one stable, no-follow descriptor.

    The descriptor identity and size are checked both before and after the
    read.  This keeps a concurrent replacement/truncation from being
    mistaken for the exact candidate even when the replacement occurs after
    the initial path check.
    """

    _reject_symlink_components(path)
    try:
        fd = _open_regular_nofollow(path)
    except OSError as exc:
        raise FlashError(f"image is unavailable: {path}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise FlashError(f"image is not a regular file: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
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
        if identity_before != identity_after or before.st_size != after.st_size:
            raise FlashError(f"image changed while being read: {path}")
        return after.st_size, digest.hexdigest()
    finally:
        os.close(fd)


def _open_regular_nofollow(path: Path) -> int:
    """Walk parent directories with ``O_NOFOLLOW`` before opening the leaf."""

    absolute = Path(os.path.abspath(path))
    components = absolute.parts
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    parent_fd = os.open(components[0], directory_flags)
    try:
        for component in components[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        leaf_flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            leaf_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            leaf_flags |= os.O_NOFOLLOW
        return os.open(components[-1], leaf_flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    """Publish one journal revision durably without clobbering a stale temp."""

    _reject_symlink_components(path.parent, "journal")
    data = json_bytes(value)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FlashError(f"journal temporary already exists: {temporary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
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


def _create_initial_json(path: Path, value: object, mode: int = 0o600) -> None:
    """Claim the final journal path exactly once before any device contact.

    Initial ownership is deliberately different from later revisions: the
    final pathname itself is created with O_EXCL/O_NOFOLLOW and fsynced.  A
    concurrent owner therefore loses before it can enumerate or mutate the
    endpoint; only an owner that successfully created this inode may use
    ``_atomic_json`` for subsequent revisions.
    """

    _reject_symlink_components(path.parent, "journal")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    data = json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
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
    except BaseException:
        # Keep a partial final inode as an ownership/reconciliation lock.  It
        # must never be removed and replaced by a second owner.
        raise


def _path_under(path: Path, parent: Path, label: str) -> Path:
    if path.is_symlink():
        raise FlashError(f"{label} must not be a symlink: {path}")
    if parent.is_symlink():
        raise FlashError(f"{label} parent must not be a symlink: {parent}")
    lexical = path if path.is_absolute() else Path.cwd() / path
    cursor = lexical.parent
    parent_lexical = parent if parent.is_absolute() else Path.cwd() / parent
    while True:
        if cursor.is_symlink():
            raise FlashError(f"{label} parent component must not be a symlink: {cursor}")
        if cursor == parent_lexical or cursor == Path(cursor.anchor or "/"):
            break
        cursor = cursor.parent
    resolved = path.resolve(strict=False)
    parent_resolved = parent.resolve(strict=False)
    try:
        resolved.relative_to(parent_resolved)
    except ValueError as exc:
        raise FlashError(f"{label} must be under {parent_resolved}") from exc
    return resolved


def _refuse_existing_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FlashError(f"journal/output already exists; replay forbidden: {path}")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FlashError(
            f"journal/output temporary already exists; replay forbidden: {temporary}"
        )


def run_text(argv: Sequence[str]) -> str:
    if not argv or argv[0] != ADB:
        raise FlashError("remapper flash accepts only the fixed adb executable")
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
        raise FlashError(
            f"command timed out after fixed {SUBPROCESS_TIMEOUT_SEC}s; argv={tuple(argv)!r}"
        ) from exc
    if result.returncode != 0:
        raise FlashError(
            f"command failed before/after flash: rc={result.returncode}; "
            f"argv={tuple(argv)!r}; stderr={result.stderr.strip()!r}"
        )
    return result.stdout.replace("\r", "")


# This indirection is intentional: tests can replace one transport owner
# without monkeypatching subprocess globally.
run_checked: Runner = run_text


def adb_shell(adb: str, serial: str, command: str) -> str:
    if adb != ADB:
        raise FlashError("remapper flash accepts only the fixed adb executable")
    return run_checked((adb, "-s", serial, "shell", command))


def parse_one_sha256(output: str) -> str:
    matches = HASH_RE.findall(output)
    if len(matches) != 1:
        raise FlashError(f"expected exactly one SHA-256, got {len(matches)}")
    return matches[0]


def parse_one_decimal(output: str) -> int:
    values = [line.strip() for line in output.splitlines() if line.strip()]
    if len(values) != 1 or DECIMAL_RE.fullmatch(values[0]) is None:
        raise FlashError(f"expected exactly one decimal value, got {values!r}")
    return int(values[0], 10)


def profile_table(root: Path | None = None) -> dict[str, dict[str, object]]:
    """Return the only permitted profile paths, hashes, and predecessors."""

    base = REPO_ROOT if root is None else Path(root)
    return {
        candidate.MODE_CONTROL: {
            "path": base / DEFAULT_CANDIDATES[candidate.MODE_CONTROL],
            "sha256": CONTROL_SHA256,
            "allowed_predecessors": set(ALLOWED_PREDECESSORS[candidate.MODE_CONTROL]),
        },
        candidate.MODE_READ: {
            "path": base / DEFAULT_CANDIDATES[candidate.MODE_READ],
            "sha256": READ_SHA256,
            "allowed_predecessors": set(ALLOWED_PREDECESSORS[candidate.MODE_READ]),
        },
        "rollback": {
            "path": DEFAULT_ROLLBACK,
            "sha256": ROLLBACK_SHA256,
            "allowed_predecessors": set(ALLOWED_PREDECESSORS["rollback"]),
        },
    }


def boot_prefix_sha256(adb: str, serial: str) -> str:
    command = (
        f"dd if={BOOT_BLOCK_RESOLVED} bs={DD_BLOCK_SIZE} "
        f"count={DD_BLOCK_COUNT} 2>/dev/null | sha256sum"
    )
    return parse_one_sha256(adb_shell(adb, serial, command))


def boot_prefix_size(adb: str, serial: str) -> int:
    command = (
        f"dd if={BOOT_BLOCK_RESOLVED} bs={DD_BLOCK_SIZE} "
        f"count={DD_BLOCK_COUNT} 2>/dev/null | wc -c"
    )
    return parse_one_decimal(adb_shell(adb, serial, command))


def _remote_staging_for_profile(profile_name: str) -> str:
    try:
        return REMOTE_STAGING_BY_PROFILE[profile_name]
    except KeyError as exc:
        raise FlashError(f"unsupported profile staging path: {profile_name!r}") from exc


def _guarded_effect_command(
    *,
    remote_staging: str,
    expected_predecessor_sha256: str,
    expected_staging_sha256: str,
    expected_predecessor_size: int = BOOT_PREFIX_SIZE,
    expected_staging_size: int = BOOT_PREFIX_SIZE,
) -> str:
    """Build the one fixed shell transaction that guards and performs dd.

    Both full-prefix hashes/sizes are sampled by the same remote shell
    transaction immediately before its only partition write.  The receipt
    lines are parsed separately so a transport response cannot be mistaken
    for a successful guarded write.
    """

    if not SHA256_RE.fullmatch(expected_predecessor_sha256):
        raise FlashError("guard predecessor hash is not exact")
    if not SHA256_RE.fullmatch(expected_staging_sha256):
        raise FlashError("guard staging hash is not exact")
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
        f"&& [ \"$staging_size\" = \"{expected_staging_size}\" ]; then "
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


def _parse_guarded_effect_receipt(
    output: str,
    *,
    expected_predecessor_sha256: str,
    expected_staging_sha256: str,
) -> dict[str, object]:
    """Require exactly one guard-pass and one successful dd result line."""

    lines = [line.strip() for line in output.replace("\r", "").splitlines() if line.strip()]
    guard_lines = [line for line in lines if line.startswith("A90V024 GUARD_PASS ")]
    dd_lines = [line for line in lines if line.startswith("A90V024 DD_RESULT ")]
    if len(guard_lines) != 1 or len(dd_lines) != 1 or len(lines) != 2:
        raise FlashError("guarded effect receipt is not exactly one guard and one dd result")

    def fields(line: str, prefix: str) -> dict[str, str]:
        payload = line[len(prefix) :]
        values: dict[str, str] = {}
        for token in payload.split():
            if "=" not in token:
                raise FlashError("guarded effect receipt field is malformed")
            key, value = token.split("=", 1)
            if not key or key in values or not value:
                raise FlashError("guarded effect receipt field is duplicate or empty")
            values[key] = value
        return values

    guard = fields(guard_lines[0], "A90V024 GUARD_PASS ")
    if set(guard) != {"current_sha256", "current_size", "staging_sha256", "staging_size"}:
        raise FlashError("guarded effect guard fields are not exact")
    if guard["current_sha256"] != expected_predecessor_sha256:
        raise FlashError("guarded effect current predecessor hash differs")
    if guard["current_size"] != str(BOOT_PREFIX_SIZE):
        raise FlashError("guarded effect current predecessor size differs")
    if guard["staging_sha256"] != expected_staging_sha256:
        raise FlashError("guarded effect staging hash differs")
    if guard["staging_size"] != str(BOOT_PREFIX_SIZE):
        raise FlashError("guarded effect staging size differs")
    result = fields(dd_lines[0], "A90V024 DD_RESULT ")
    if set(result) != {"rc", "count"} or result["rc"] != "0" or result["count"] != str(DD_BLOCK_COUNT):
        raise FlashError("guarded effect dd result is not exactly one successful write")
    return {
        "schema": GUARDED_EFFECT_SCHEMA,
        "guard": guard,
        "dd_result": result,
        "write_count": 1,
    }


def _require_exact_twrp(adb: str, endpoint: AdbEndpoint) -> None:
    help_text = adb_shell(adb, endpoint.serial, "twrp --help 2>&1")
    if "TWRP openrecoveryscript command line tool" not in help_text:
        raise FlashError("bound endpoint is not the expected TWRP CLI")
    if f"TWRP version {TWRP_VERSION}" not in help_text:
        raise FlashError("bound endpoint TWRP version differs from the proved build")
    resolved = adb_shell(
        adb, endpoint.serial, f"readlink -f {BOOT_BLOCK_ALIAS}"
    ).strip()
    if resolved != BOOT_BLOCK_RESOLVED:
        raise FlashError(f"boot node resolved unexpectedly: {resolved!r}")


def _revalidate_recovery(adb: str, initial: AdbEndpoint) -> AdbEndpoint:
    """Re-enumerate the exact endpoint and recheck TWRP/boot alias identity."""

    current = select_exact_recovery(
        adb,
        run=run_checked,
        expected_serial_sha256=TARGET_SERIAL_SHA256,
    )
    if (
        current.serial != initial.serial
        or current.serial_sha256 != initial.serial_sha256
        or current.serial_sha256 != TARGET_SERIAL_SHA256
    ):
        raise FlashError("recovery endpoint changed while staging was active")
    _require_exact_twrp(adb, current)
    return current


def _validate_local_profile(profile: Mapping[str, object]) -> tuple[Path, str]:
    image_obj = profile.get("path")
    expected_hash = profile.get("sha256")
    if not isinstance(image_obj, Path) or not isinstance(expected_hash, str):
        raise FlashError("profile has malformed image path/hash")
    _reject_symlink_components(image_obj)
    image = image_obj
    image_size, actual_hash = _stable_file_digest(image)
    if image_size != BOOT_PREFIX_SIZE:
        raise FlashError(
            f"image size {image_size} != fixed {BOOT_PREFIX_SIZE}"
        )
    if actual_hash != expected_hash:
        raise FlashError(f"image SHA-256 mismatch: {actual_hash} != {expected_hash}")
    return image, expected_hash


def _cleanup_remote(
    adb: str, endpoint: AdbEndpoint, remote_staging: str
) -> tuple[bool, str | None]:
    """Remove fixed staging and prove absence, retaining cleanup failures."""

    error: str | None = None
    try:
        adb_shell(adb, endpoint.serial, f"rm -f {remote_staging}")
    except Exception as exc:  # cleanup must be attempted and reported
        error = f"{type(exc).__name__}: {exc}"
    absent = False
    if error is None:
        try:
            marker = adb_shell(
                adb,
                endpoint.serial,
                f"if [ -e {remote_staging} ] || [ -L {remote_staging} ]; then echo present; "
                "else echo absent; fi",
            ).strip()
            absent = marker == "absent"
            if not absent:
                error = f"remote staging cleanup marker was {marker!r}"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
    return absent, error


def flash(args: argparse.Namespace) -> Path:
    """Perform one exact profile transition and durably journal each phase.

    The journal is created before target discovery and is never overwritten by
    a second invocation.  It is therefore both the pre-effect intent record
    and the post-effect receipt.  In particular, a transport error after the
    ``dd`` command has been marked started as ``AMBIGUOUS_AFTER_EFFECT``;
    callers must reconcile externally and cannot replay this tool.
    """

    if not getattr(args, "execute", False):
        raise FlashError("remapper flash requires explicit --execute")
    if hasattr(args, "adb") and getattr(args, "adb") != ADB:
        raise FlashError("remapper flash accepts only the fixed adb executable")
    adb = ADB
    profile_name = getattr(args, "profile", None)
    if profile_name not in PROFILES:
        raise FlashError(f"unsupported flash profile: {profile_name!r}")

    # ``receipt``, ``journal``, and redirected ``output_root`` were historical
    # replay namespaces.  Refuse them when an embedding caller tries to inject
    # one; merely omitting parser options is insufficient because callers can
    # pass arbitrary Namespace attributes directly.
    for selector in ("receipt", "journal"):
        if hasattr(args, selector) and getattr(args, selector) is not None:
            raise FlashError(
                f"{selector} selector is disabled; remapper journal is fixed under REPO_ROOT"
            )
    if hasattr(args, "output_root"):
        # The parser has no output-root option.  Reject even an equal injected
        # value so an embedding caller cannot turn this into a second selector
        # namespace by relying on a superficially matching path.
        raise FlashError(
            "output_root selector is disabled; remapper journal is fixed under REPO_ROOT"
        )

    root_input = Path(REPO_ROOT)
    _reject_symlink_components(root_input)
    root = root_input.resolve()
    journal_path = root / "evidence" / "private" / (
        f"verification-024-remapper-boot-flash-{profile_name}.journal.json"
    )
    journal_path = _path_under(journal_path, root / "evidence" / "private", "flash journal")
    # Replay/output refusal is checked before even hashing a candidate.  A
    # stale journal is an explicit stop condition independent of local files.
    _refuse_existing_output(journal_path)

    profiles = profile_table(root)
    profile = profiles[profile_name]
    image, expected_hash = _validate_local_profile(profile)
    remote_staging = _remote_staging_for_profile(profile_name)
    allowed = profile.get("allowed_predecessors")
    if not isinstance(allowed, (set, frozenset)):
        raise FlashError("profile predecessor set is malformed")
    allowed = set(allowed)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    journal: dict[str, object] = {
        "schema": "sdm855-a90-remapper-boot-flash-private-v1",
        "status": "INTENT_DURABLE_PRE_EFFECT",
        "profile": profile_name,
        "started_utc": started,
        "target_model": TARGET_MODEL,
        "target_device": TARGET_DEVICE,
        "boot_alias": BOOT_BLOCK_ALIAS,
        "boot_node": BOOT_BLOCK_RESOLVED,
        "image_sha256": expected_hash,
        "image_size": BOOT_PREFIX_SIZE,
        "allowed_predecessors": sorted(allowed),
        # The profile-owned remote path is part of the producer contract from
        # the first durable intent record onward; it is never inferred from
        # a later caller-selected value.
        "remote_staging": remote_staging,
        "effect_dispatched": False,
        "effect_armed": False,
        # These explicit replay/ambiguity controls are part of the producer
        # contract consumed by torn-boot recovery and the finalizer.  Keep
        # them present even on the pre-effect intent so an interrupted
        # journal cannot be interpreted by omission.
        "effect_ambiguous": False,
        "effect_replayed": False,
        "automatic_retries": False,
        "write_count": 0,
        "partition_writes": False,
        "reboot_dispatched": False,
        "staging_cleanup_deferred": False,
        "staging_attempted": False,
        "staging_attempt_count": 0,
        "staging_status": None,
        "remote_staging_sha256": None,
        "remote_staging_size": None,
        "post_staging_predecessor_sha256": None,
        "post_staging_predecessor_size": None,
        "post_staging_predecessor_revalidated": False,
        "staging_removed": False,
        "cleanup_intent": None,
        "cleanup_intent_result": None,
        "cleanup_error": None,
        "physical_effect_claim": {
            "claimed": False,
            "attempted": False,
            "key_sha256": None,
            "claim_path": None,
            "claim_sha256": None,
            "claim_size": None,
        },
        "current_state": None,
        "error": None,
    }
    _create_initial_json(journal_path, journal)

    endpoint: AdbEndpoint | None = None
    endpoint_bound = False
    endpoints: tuple[AdbEndpoint, ...] = ()
    effect_started = False
    cleanup_ok = False
    cleanup_error: str | None = None
    staging_attempted = False
    physical_claim_data: bytes | None = None
    physical_claim_key_sha256: str | None = None
    physical_claim_path: Path | None = None
    physical_claim_attempted = False
    physical_claimed = False

    try:
        # This helper enumerates ADB and probes only the endpoint whose serial
        # hash is pinned.  Other endpoints are counted for evidence but never
        # selected.
        endpoint = select_exact_recovery(
            adb,
            run=run_checked,
            expected_serial_sha256=TARGET_SERIAL_SHA256,
        )
        endpoints = parse_adb_devices(run_checked((adb, "devices")))
        bound = [item for item in endpoints if item.serial == endpoint.serial]
        if len(bound) != 1 or endpoint.serial_sha256 != TARGET_SERIAL_SHA256:
            raise FlashError("exact pinned A90 recovery endpoint was not uniquely bound")
        _require_exact_twrp(adb, endpoint)
        # Do not treat a merely matching serial as cleanup authority.  The
        # endpoint is bound only after the exact TWRP build and boot alias
        # have both passed; wrong-recovery failures therefore issue no later
        # device command from finally.
        endpoint_bound = True

        before_hash = boot_prefix_sha256(adb, endpoint.serial)
        before_size = boot_prefix_size(adb, endpoint.serial)
        if before_size != BOOT_PREFIX_SIZE:
            raise FlashError(f"pre-write boot prefix size mismatch: {before_size}")
        if before_hash not in allowed:
            raise FlashError(
                f"boot prefix predecessor {before_hash} is not allowed for {profile_name}"
            )
        journal.update(
            {
                "target_serial_sha256": endpoint.serial_sha256,
                "other_adb_endpoints_untouched": max(0, len(endpoints) - 1),
                "predecessor_sha256": before_hash,
                "predecessor_size": before_size,
                "status": "PRE_EFFECT_READY",
            }
        )
        _atomic_json(journal_path, journal)

        # Publish cleanup intent before obtaining mutation authority.  The
        # following fresh rebind and remove/absence proof are contiguous, so
        # no journal fsync is inserted between the final bind and ``rm``.
        journal["cleanup_intent"] = {
            "phase": "pre_staging",
            "status": "CLEANUP_INTENT_DURABLE",
            "remote_staging": remote_staging,
        }
        _atomic_json(journal_path, journal)
        endpoint = _revalidate_recovery(adb, endpoint)
        pre_cleanup_ok, pre_cleanup_error = _cleanup_remote(
            adb, endpoint, remote_staging
        )
        journal.update(
            {
                "pre_cleanup_target_serial_sha256": endpoint.serial_sha256,
                "pre_cleanup_revalidated": True,
                "pre_staging_removed": pre_cleanup_ok,
                "pre_cleanup_error": pre_cleanup_error,
                "cleanup_intent_result": "PROVED" if pre_cleanup_ok else "FAILED",
            }
        )
        _atomic_json(journal_path, journal)
        if not pre_cleanup_ok:
            journal["staging_cleanup_deferred"] = True
            journal["reconcile_required"] = True
            raise FlashError(
                f"stale remote staging could not be removed: {pre_cleanup_error}"
            )

        # A push may partially complete before its transport receipt returns;
        # mark that staging attempt so a pre-effect cleanup can be reconciled
        # exactly once if needed.
        staging_attempted = True
        # A push can partially complete before its transport result arrives.
        # Publish the attempt before invoking it so an interrupted attempt is
        # represented durably and can only take the pre-effect cleanup path.
        journal.update(
            {
                "staging_attempted": True,
                "staging_attempt_count": 1,
                "staging_dispatch_count": 1,
                "staging_status": "STAGING_PUSH_STARTED",
            }
        )
        _atomic_json(journal_path, journal)
        # The staging-attempt marker is durable.  Rebind immediately after it
        # and invoke push with no fsync or device command between the bind and
        # the transfer.  The returned binding is persisted only after push
        # returns (or conservatively omitted on an ambiguous failure).
        endpoint = _revalidate_recovery(adb, endpoint)
        journal["staging_rebind_after_attempt"] = True
        journal["staging_rebind_target_serial_sha256"] = endpoint.serial_sha256
        run_checked((adb, "-s", endpoint.serial, "push", str(image), remote_staging))
        journal.update(
            {
                "pre_push_target_serial_sha256": endpoint.serial_sha256,
                "pre_push_revalidated": True,
                "staging_status": "STAGING_PUSH_RETURNED",
            }
        )
        _atomic_json(journal_path, journal)
        remote_hash = parse_one_sha256(
            adb_shell(adb, endpoint.serial, f"sha256sum {remote_staging}")
        )
        remote_size = parse_one_decimal(
            adb_shell(adb, endpoint.serial, f"wc -c < {remote_staging}")
        )
        journal.update(
            {
                "remote_staging_sha256": remote_hash,
                "remote_staging_size": remote_size,
            }
        )
        _atomic_json(journal_path, journal)
        if remote_hash != expected_hash or remote_size != BOOT_PREFIX_SIZE:
            raise FlashError(
                "remote staging verification mismatch: "
                f"sha256={remote_hash!r} size={remote_size!r}"
            )

        # Staging is a window in which recovery can disappear/rebind.  Bind
        # the exact serial, TWRP build, and boot alias again before preparing
        # the write, then re-read the complete boot prefix.  The predecessor
        # must still be exactly the same bytes observed before staging before
        # the durable effect marker can be published.
        endpoint = _revalidate_recovery(adb, endpoint)
        journal.update(
            {
                "post_staging_target_serial_sha256": endpoint.serial_sha256,
                "post_staging_rebind_serial_sha256": endpoint.serial_sha256,
                "post_staging_revalidated": True,
            }
        )
        post_staging_predecessor_hash = boot_prefix_sha256(adb, endpoint.serial)
        post_staging_predecessor_size = boot_prefix_size(adb, endpoint.serial)
        journal.update(
            {
                "post_staging_predecessor_sha256": post_staging_predecessor_hash,
                "post_staging_predecessor_size": post_staging_predecessor_size,
                "post_staging_predecessor_revalidated": True,
            }
        )
        _atomic_json(journal_path, journal)
        if (
            post_staging_predecessor_hash != before_hash
            or post_staging_predecessor_size != before_size
        ):
            raise FlashError(
                "boot prefix predecessor changed after staging: "
                f"before={before_hash}/{before_size} "
                f"after={post_staging_predecessor_hash}/{post_staging_predecessor_size}"
            )
        endpoint = _revalidate_recovery(adb, endpoint)
        journal.update(
            {
                "pre_effect_target_serial_sha256": endpoint.serial_sha256,
                "pre_effect_rebind_serial_sha256": endpoint.serial_sha256,
                "pre_effect_revalidated": True,
            }
        )

        # Reserve the physical boot-prefix preimage independently of the
        # requested profile and output journal.  This is intentionally after
        # the post-staging predecessor equality check and before the durable
        # effect marker.  A concurrent READ/ROLLBACK owner with the same
        # current bytes therefore loses before either can issue its dd.
        _claim_identity, physical_claim_key_sha256 = boot_prefix_claim_identity(
            before_hash,
            before_size,
        )
        physical_claim_path = boot_prefix_claim_path(root, physical_claim_key_sha256)
        physical_claim_attempted = True
        physical = journal["physical_effect_claim"]
        assert isinstance(physical, dict)
        physical.update(
            {
                "attempted": True,
                "key_sha256": physical_claim_key_sha256,
                "claim_path": str(physical_claim_path),
            }
        )
        claim = claim_boot_prefix(
            root,
            current_preimage_sha256=before_hash,
            current_preimage_size=before_size,
            experiment_id=f"normal-remapper-{profile_name}",
            provenance={
                "owner_kind": "normal-remapper",
                "profile": profile_name,
                "predecessor_sha256": before_hash,
                "predecessor_size": before_size,
                "image_sha256": expected_hash,
                "image_size": BOOT_PREFIX_SIZE,
                "journal_path": str(journal_path),
            },
        )
        physical_claim_data = claim.data
        physical_claimed = True
        physical.update(
            {
                "claimed": True,
                "claim_sha256": hashlib.sha256(physical_claim_data).hexdigest(),
                "claim_size": len(physical_claim_data),
            }
        )
        _atomic_json(journal_path, journal)

        # Mark the only partition write durable before sending it.  A failure
        # here leaves a replay-forbidden journal without touching the device.
        journal.update(
            {
                "status": "EFFECT_DISPATCH_STARTED",
                "effect_dispatched": True,
                "effect_armed": True,
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
        # Treat the publication call itself as an ambiguous one-way boundary:
        # a crash after replace/fsync but before the call returns must never
        # enter the pre-effect cleanup path.
        effect_started = True
        _atomic_json(journal_path, journal)
        # The marker is now durable.  From this point onward the transaction
        # cannot safely issue cleanup on any failure because the sole write
        # may have happened even when the transport returned no answer.

        # A durable dispatch marker is a one-way boundary.  Revalidate the
        # pinned endpoint and TWRP/boot alias again after that marker, then
        # perform the predecessor/staging guards and sole partition write in
        # one fixed remote shell transaction.  A guard failure is ambiguous;
        # no cleanup or replay is permitted.
        endpoint = _revalidate_recovery(adb, endpoint)
        journal.update(
            {
                "post_dispatch_target_serial_sha256": endpoint.serial_sha256,
                "post_dispatch_rebind_serial_sha256": endpoint.serial_sha256,
                "post_dispatch_revalidated": True,
                "final_target_serial_sha256": endpoint.serial_sha256,
                "final_rebind_serial_sha256": endpoint.serial_sha256,
                "final_revalidated": True,
            }
        )
        guarded_command = _guarded_effect_command(
            remote_staging=remote_staging,
            expected_predecessor_sha256=before_hash,
            expected_staging_sha256=expected_hash,
            expected_predecessor_size=before_size,
            expected_staging_size=BOOT_PREFIX_SIZE,
        )
        write_output = adb_shell(adb, endpoint.serial, guarded_command)
        guarded_receipt = _parse_guarded_effect_receipt(
            write_output,
            expected_predecessor_sha256=before_hash,
            expected_staging_sha256=expected_hash,
        )
        guard = guarded_receipt.get("guard")
        if not isinstance(guard, Mapping):
            raise FlashError("guarded effect receipt guard projection is missing")
        journal.update(
            {
                "status": "EFFECT_RETURNED_VERIFYING_READBACK",
                "write_output_tail": write_output[-512:],
                "guarded_effect_command": guarded_command,
                "guarded_effect_receipt": guarded_receipt,
                # Project the guard only after the returned receipt has been
                # parsed and matched.  These values are absent on an
                # ambiguous transport failure before a receipt returns.
                "post_dispatch_predecessor_sha256": guard["current_sha256"],
                "post_dispatch_predecessor_size": int(guard["current_size"]),
                "post_dispatch_staging_sha256": guard["staging_sha256"],
                "post_dispatch_staging_size": int(guard["staging_size"]),
            }
        )
        _atomic_json(journal_path, journal)

        after_hash = boot_prefix_sha256(adb, endpoint.serial)
        after_size = boot_prefix_size(adb, endpoint.serial)
        journal.update(
            {
                "readback_sha256": after_hash,
                "readback_size": after_size,
            }
        )
        if after_hash != expected_hash or after_size != BOOT_PREFIX_SIZE:
            raise FlashError(
                "post-write boot prefix verification mismatch: "
                f"sha256={after_hash!r} size={after_size!r}"
            )
        journal["status"] = "READBACK_VERIFIED"
    except BaseException as exc:
        journal["error"] = f"{type(exc).__name__}: {exc}"
        journal["status"] = (
            "AMBIGUOUS_AFTER_EFFECT_RECONCILE_REQUIRED"
            if effect_started
            else "REFUSED_PRE_EFFECT"
        )
        if effect_started:
            # A post-marker transport/readback failure leaves the current
            # partition state unknown.  The standalone torn-write rescue is
            # authorized only by this explicit producer assertion.
            journal.update(
                {
                    "current_state": "UNKNOWN",
                    "effect_armed": True,
                    "partition_writes": True,
                    "staging_cleanup_deferred": True,
                    "reconcile_required": True,
                    "effect_ambiguous": True,
                    "automatic_retries": False,
                }
            )
        _atomic_json(journal_path, journal)
        raise
    finally:
        # Cleanup is safe before the effect marker and after a complete,
        # verified readback.  Every other post-marker outcome is ambiguous or
        # otherwise requires reconciliation; do not send any further ADB
        # command, including removal of the remote staging object.
        cleanup_allowed = (
            endpoint is not None
            and endpoint_bound
            and staging_attempted
            and (not effect_started or journal.get("status") == "READBACK_VERIFIED")
        )
        cleanup_rebind_failed = False
        if cleanup_allowed and endpoint is not None:
            # Publish cleanup intent before obtaining the authority used for
            # the final cleanup.  The rebind and cleanup then run
            # contiguously; binding/result fields are recorded only after the
            # remove/absence proof returns.
            journal["cleanup_intent"] = {
                "phase": "terminal_staging_cleanup",
                "status": "CLEANUP_INTENT_DURABLE",
                "remote_staging": remote_staging,
            }
            try:
                _atomic_json(journal_path, journal)
                endpoint = _revalidate_recovery(adb, endpoint)
                cleanup_ok, cleanup_error = _cleanup_remote(
                    adb, endpoint, remote_staging
                )
                journal.update(
                    {
                        "final_cleanup_target_serial_sha256": endpoint.serial_sha256,
                        "final_cleanup_revalidated": True,
                        "staging_removed": cleanup_ok,
                        "cleanup_error": cleanup_error,
                        "cleanup_intent_result": (
                            "PROVED" if cleanup_ok else "FAILED"
                        ),
                    }
                )
            except BaseException as exc:
                cleanup_rebind_failed = True
                cleanup_ok = False
                cleanup_error = (
                    f"final cleanup Recovery rebind failed: {type(exc).__name__}: {exc}"
                )
                journal.update(
                    {
                        "staging_removed": False,
                        "staging_cleanup_deferred": True,
                        "cleanup_rebind_failed": True,
                        "cleanup_error": cleanup_error,
                        "reconcile_required": True,
                    }
                )
                if effect_started:
                    journal["current_state"] = "UNKNOWN"
                if journal.get("status") == "READBACK_VERIFIED":
                    journal["status"] = "CLEANUP_REBIND_FAILED_RECONCILIATION_REQUIRED"
                _atomic_json(journal_path, journal)
            try:
                _atomic_json(journal_path, journal)
            except BaseException:
                # The original effect outcome is already durable.  Preserve
                # the in-memory error for the final check below and never
                # attempt another device command.
                if cleanup_error is None:
                    cleanup_error = "failed to update final cleanup journal"
                    journal["cleanup_error"] = cleanup_error
                if journal.get("status") == "READBACK_VERIFIED":
                    journal["status"] = "CLEANUP_FAILED"
            if cleanup_allowed and not cleanup_rebind_failed and endpoint is not None:
                if cleanup_error is not None:
                    # A failed cleanup after a recorded staging attempt is
                    # still pre-effect only when the dispatch marker was not
                    # armed, but the remote path remains an explicit
                    # reconciliation obligation.
                    journal["staging_cleanup_deferred"] = True
                    journal["reconcile_required"] = True
                # Do not let cleanup replace an already-ambiguous status.  A
                # failed cleanup remains evidence, but never grants replay.
                if (
                    cleanup_error is not None
                    and journal.get("status") == "READBACK_VERIFIED"
                ):
                    journal["status"] = "CLEANUP_FAILED"
                try:
                    _atomic_json(journal_path, journal)
                except BaseException:
                    # The original effect outcome is already durable. Preserve
                    # the in-memory error and never attempt another device
                    # command.
                    if cleanup_error is None:
                        cleanup_error = "failed to update final cleanup journal"
                        journal["cleanup_error"] = cleanup_error
                    if journal.get("status") == "READBACK_VERIFIED":
                        journal["status"] = "CLEANUP_FAILED"
        elif effect_started:
            cleanup_ok = False
            cleanup_error = "deferred after effect marker; reconciliation required"
            journal.update(
                {
                    "staging_removed": False,
                    "staging_cleanup_deferred": True,
                    "cleanup_error": cleanup_error,
                    "reconcile_required": True,
                }
            )
            # This is host-only evidence.  In particular, do not call
            # _cleanup_remote here or in any exception path after dd marker.
            _atomic_json(journal_path, journal)

    journal["completed_utc"] = dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0
    ).isoformat()
    if journal.get("status") == "READBACK_VERIFIED" and cleanup_ok:
        journal["status"] = "PASS_READBACK_AND_CLEANUP"
    # This update is host-only.  It intentionally happens after cleanup and
    # retains the status above, including any ambiguous/cleanup failure.
    try:
        _atomic_json(journal_path, journal)
    except BaseException:
        # An existing journal is still present and forbids replay; surface the
        # publication failure rather than pretending the transition closed.
        raise
    if journal.get("status") != "PASS_READBACK_AND_CLEANUP":
        raise FlashError(f"remapper flash did not close cleanly; evidence={journal_path}")
    if not cleanup_ok:
        raise FlashError(f"remote staging cleanup was not proved; evidence={journal_path}")
    return journal_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--execute", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    path = flash(args)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
