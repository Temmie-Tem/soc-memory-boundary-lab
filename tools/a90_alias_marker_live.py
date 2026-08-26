#!/usr/bin/env python3
"""Canonical Verification 018 A90 storage-identity acquisition runner.

The runner speaks only to the pinned loopback A90P1 bridge.  It validates the
exact A90 V2321 target, uploads a caller-selected already-built probe through
fixed temporary paths, creates one fixed ION character node, runs one fixed
camera-preview marker acquisition, removes every temporary object, and proves
the final runtime health.  Probe interpretation is deliberately left to the
host-side analyzer.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from typing import Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.a90_acm_snapshot import Command, Frame, exchange
from tools import a90_alias_marker_analysis as marker_analysis


SCHEMA = "a90_alias_marker_live_v1"
PROBE_SCHEMA = "a90_alias_marker_v1"

# Deliberately stricter than the older collectors: V018 cannot move to a
# different local listener or an IPv6/hostname alias.
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 54321

EXPECTED_VERSION = "A90 Linux init 0.9.285"
EXPECTED_BUILD = "build=v2321-usb-clean-identity-rodata"
EXPECTED_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
EXPECTED_MODEL = "SM-A908N"
EXPECTED_SOC = "SM8150"
EXPECTED_RUNTIME = "0.9.285"
EXPECTED_RUNTIME_BUILD = "v2321-usb-clean-identity-rodata"
EXPECTED_BOOTLOADER = "A908NKSU5EWA3"
EXPECTED_CMDLINE_TOKENS = frozenset(
    {
        "androidboot.em.model=SM-A908N",
        "androidboot.bootloader=A908NKSU5EWA3",
        "androidboot.debug_level=0x4f4c",
        "androidboot.force_upload=0x0",
        "sec_debug.dump_sink=0x0",
    }
)

REMOTE_ROOT = "/tmp/a90-native"
REMOTE_ENVELOPE = f"{REMOTE_ROOT}/v018-alias-probe.b64u"
REMOTE_BINARY = f"{REMOTE_ROOT}/v018-alias-probe"
REMOTE_ION = f"{REMOTE_ROOT}/v018-ion"
ION_DEV_PATH = "/sys/class/misc/ion/dev"
TOYBOX = "/bin/toybox"

EXPECTED_HEAP = "camera_preview"
EXPECTED_MIB = 256
EXPECTED_ANCHORS = 4
EXPECTED_TRIALS = 2
EXPECTED_SEED = "0x5da9f0e3c17b2846"
EXPECTED_ION_DEV = "10:94"

# These pins are deliberately checked before the first bridge command.  They
# are filled from the final checked-in C source and two byte-identical static
# builds; a caller cannot substitute a merely self-consistent binary/receipt.
EXPECTED_PROBE_SOURCE_BASENAME = "a90_alias_marker_probe.c"
EXPECTED_PROBE_BINARY_BASENAME = "v018-alias-probe"
EXPECTED_PROBE_SOURCE_SIZE = 22191
EXPECTED_PROBE_SOURCE_SHA256 = "cdc6f985fb8e2f37a3964a25f8d575ec1b3fe48eab71d084a30537c6fbe6f3bb"
EXPECTED_PROBE_BINARY_SIZE = 710408
EXPECTED_PROBE_BINARY_SHA256 = "33ef21a13ef79f6888b5a466644660ace3c6950664b1e2b497aad474f1487d56"
BUILD_SCHEMA = "a90_alias_marker_build_v1"
BRIDGE_PROCESS_SCRIPT = "serial_tcp_bridge.py"
BRIDGE_SERIAL_DEVICE = "/dev/ttyACM0"
BRIDGE_SERIAL_ID = "/dev/serial/by-id/usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00"
BRIDGE_SERIAL_GLOB_TOKEN = "usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00"
BRIDGE_SCRIPT_SOURCE = "serial_tcp_bridge.py"

# This is the one place to adapt if the concurrently-built probe changes its
# argument layout.  The current probe has the heap/size/anchor/trial constants
# compiled in and accepts only the fixed node and seed flags.  No caller-
# provided command or path is accepted.
PROBE_CLI_ARGS: tuple[str, ...] = (
    "--ion-node",
    REMOTE_ION,
    "--seed",
    EXPECTED_SEED,
)
PROBE_ARGV: tuple[str, ...] = ("run", REMOTE_BINARY, *PROBE_CLI_ARGS)

MAX_LEGACY_CHUNK = 3500
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
DEFAULT_TOTAL_TIMEOUT = 900.0
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
EXIT_RE = re.compile(rb"(?:^|\r?\n)\[exit ([0-9]+)\](?:\r?\n|$)")
RUN_PREFIX_RE = re.compile(rb"run: pid=[0-9]+, q/Ctrl-C cancels")
RUN_PID_RE = re.compile(rb"(?:^|\r?\n)run: pid=([0-9]+), q/Ctrl-C cancels(?:\r?\n|$)")
HASH_LINE_RE = re.compile(rb"(?m)^([0-9a-f]{64})  (\S+)\s*$")
SELFTEST_RE = re.compile(
    rb"(?m)^selftest:\s+pass=(?P<passed>[0-9]+)\s+"
    rb"warn=(?P<warn>[0-9]+)\s+fail=(?P<fail>[0-9]+)\s+"
    rb"duration=(?P<duration>[0-9]+)ms\s+entries=(?P<entries>[0-9]+)\s*$"
)

RAW_BASENAME = "alias-marker.jsonl"
RAW_PAYLOAD_BASENAME = "probe-output.bin"
TRANSCRIPT_BASENAME = "transcript.bin"
RECEIPT_BASENAME = "receipt.json"

BRIDGE_SCRIPT_PATH = REPO_ROOT / "tools" / "a90_acm_snapshot.py"
RUNNER_SCRIPT_PATH = Path(__file__).resolve()


class LiveError(RuntimeError):
    """Raised for any V018 acquisition or evidence-contract failure."""


@dataclass(frozen=True)
class ExtendedCommand:
    """Newline-safe command used only for the base64 envelope delimiters."""

    evidence_id: str
    argv: tuple[str, ...]

    @property
    def wire(self) -> bytes:
        fields: list[str] = []
        for argument in self.argv:
            data = argument.encode("utf-8")
            if b"\0" in data:
                raise LiveError("cmdv1x argument contains NUL")
            fields.append(f"{len(data)}:{data.hex()}")
        wire = ("cmdv1x " + " ".join(fields) + "\n").encode("ascii")
        if len(wire) >= 4096:
            raise LiveError(f"cmdv1x frame is not bounded: {len(wire)} bytes")
        return wire


@dataclass
class _Session:
    host: str
    port: int
    timeout: float
    deadline: float | None = None
    transcript_parts: list[bytes] = field(default_factory=list)
    commands: list[dict[str, object]] = field(default_factory=list)

    def invoke(
        self,
        evidence_id: str,
        argv: tuple[str, ...],
        timeout: float | None = None,
        *,
        extended: bool = False,
        allow_error: bool = False,
    ) -> Frame:
        try:
            if self.deadline is not None and time.monotonic() >= self.deadline:
                raise LiveError("V018 total acquisition deadline expired")
            frame = call(
                self.host,
                self.port,
                evidence_id,
                argv,
                self.timeout if timeout is None else timeout,
                extended=extended,
                allow_error=allow_error,
            )
            if len(frame.transcript) > MAX_FRAME_BYTES or len(frame.payload) > MAX_PAYLOAD_BYTES:
                raise LiveError(f"{evidence_id} frame exceeds the bounded evidence size")
            if frame.begin.get("cmd") != argv[0] or frame.end.get("cmd") != argv[0]:
                raise LiveError(f"{evidence_id} frame command does not match argv")
            if frame.begin.get("seq") != frame.end.get("seq"):
                raise LiveError(f"{evidence_id} frame sequence differs at END")
        except BaseException as exc:
            self.commands.append(
                {
                    "evidence_id": evidence_id,
                    "argv": list(argv),
                    "extended": extended,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            raise
        self.transcript_parts.append(
            f"\n===== {evidence_id} =====\n".encode("ascii") + frame.transcript
        )
        self.commands.append(
            {
                "evidence_id": evidence_id,
                "argv": list(argv),
                "extended": extended,
                "begin": dict(frame.begin),
                "end": dict(frame.end),
                "transcript_sha256": sha256(frame.transcript),
                "transcript_size": len(frame.transcript),
            }
        )
        return frame


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _open_read_nofollow(path: Path, label: str) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LiveError(f"{label} cannot be opened without following links") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise LiveError(f"{label} is not a regular file: {path}")
        if info.st_size < 0 or info.st_size > MAX_INPUT_BYTES:
            raise LiveError(f"{label} exceeds the bounded input size")
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def read_stable(path: Path, label: str) -> bytes:
    """Read a regular input without following links and verify stable identity."""

    path = Path(path)
    fd, before = _open_read_nofollow(path, label)
    try:
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise LiveError(f"{label} truncated while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    before_key = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_key = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_key != after_key:
        raise LiveError(f"{label} changed while being read")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise LiveError(f"{label} size changed while being read")
    return data


def _json_document(data: bytes, label: str) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LiveError(f"{label} is not UTF-8") from exc

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise LiveError(f"{label} repeats key {key!r}")
            result[key] = value
        return result

    def reject(value: str) -> object:
        raise LiveError(f"{label} contains non-finite JSON number {value!r}")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=reject)
    except LiveError:
        raise
    except json.JSONDecodeError as exc:
        raise LiveError(f"{label} is malformed JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise LiveError(f"{label} is not a JSON object")
    return value


def _artifact_descriptor(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"basename", "size_bytes", "sha256"}:
        raise LiveError(f"{label} descriptor fields differ")
    basename = value.get("basename")
    if not isinstance(basename, str) or SAFE_ID_RE.fullmatch(basename) is None:
        raise LiveError(f"{label} descriptor basename is unsafe")
    size = value.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise LiveError(f"{label} descriptor size is invalid")
    digest = value.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
        raise LiveError(f"{label} descriptor hash is invalid")
    return {"basename": basename, "size_bytes": size, "sha256": digest.lower()}


def validate_build_receipt(
    data: bytes,
    *,
    source: Mapping[str, object],
    binary: Mapping[str, object],
    label: str = "build receipt",
) -> dict[str, object]:
    """Require a pinned, reproducible static build before bridge contact."""

    receipt = _json_document(data, label)
    required = {"schema", "source", "binary", "compiler", "reproducible_byte_identical"}
    if set(receipt) != required or receipt.get("schema") != BUILD_SCHEMA:
        raise LiveError(f"{label} top-level fields/schema differ")
    receipt_source = _artifact_descriptor(receipt.get("source"), f"{label} source")
    receipt_binary = _artifact_descriptor(receipt.get("binary"), f"{label} binary")
    if receipt_source != dict(source) or receipt_binary != dict(binary):
        raise LiveError(f"{label} does not bind the exact source and binary")
    if receipt_source["basename"] != EXPECTED_PROBE_SOURCE_BASENAME:
        raise LiveError(f"{label} source basename differs")
    if receipt_binary["basename"] != EXPECTED_PROBE_BINARY_BASENAME:
        raise LiveError(f"{label} binary basename differs")
    if (
        not EXPECTED_PROBE_SOURCE_SHA256
        or source["basename"] != EXPECTED_PROBE_SOURCE_BASENAME
        or source["size_bytes"] != EXPECTED_PROBE_SOURCE_SIZE
        or source["sha256"] != EXPECTED_PROBE_SOURCE_SHA256
        or binary["basename"] != EXPECTED_PROBE_BINARY_BASENAME
        or binary["size_bytes"] != EXPECTED_PROBE_BINARY_SIZE
        or binary["sha256"] != EXPECTED_PROBE_BINARY_SHA256
    ):
        raise LiveError("V018 source/binary pins are unset or do not match the final build")
    compiler = receipt.get("compiler")
    if not isinstance(compiler, Mapping) or set(compiler) != {
        "triple", "version", "command", "static",
    }:
        raise LiveError(f"{label} compiler identity fields differ")
    if (
        compiler.get("triple") != "aarch64-linux-gnu"
        or not isinstance(compiler.get("version"), str)
        or not compiler["version"].strip()
        or not isinstance(compiler.get("command"), list)
        or not compiler["command"]
        or any(not isinstance(item, str) or not item for item in compiler["command"])
        or compiler.get("static") is not True
        or receipt.get("reproducible_byte_identical") is not True
    ):
        raise LiveError(f"{label} compiler/build reproducibility proof is incomplete")
    return {
        "schema": BUILD_SCHEMA,
        "compiler_triple": compiler["triple"],
        "compiler_version": compiler["version"],
        "static": True,
        "reproducible_byte_identical": True,
    }


def _proc_cmdline(pid: int) -> list[str] | None:
    path = Path("/proc") / str(pid) / "cmdline"
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        data = os.read(fd, 64 * 1024)
    finally:
        os.close(fd)
    if not data:
        return None
    return [item.decode("utf-8", errors="replace") for item in data.split(b"\0") if item]


def _option_values(argv: Sequence[str], option: str) -> list[str]:
    return [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == option]


def validate_bridge_binding() -> dict[str, object]:
    """Bind the loopback listener to the unique configured A90 serial bridge."""

    if os.path.realpath(BRIDGE_SERIAL_ID) != BRIDGE_SERIAL_DEVICE:
        raise LiveError("the configured A90 serial identity does not resolve to /dev/ttyACM0")
    try:
        info = os.stat(BRIDGE_SERIAL_DEVICE)
    except OSError as exc:
        raise LiveError("the configured A90 serial device is unavailable") from exc
    if not stat.S_ISCHR(info.st_mode):
        raise LiveError("the configured A90 serial path is not a character device")
    matches: list[int] = []
    try:
        proc_entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise LiveError("cannot enumerate /proc for bridge binding") from exc
    for entry in proc_entries:
        if not entry.name.isdigit():
            continue
        argv = _proc_cmdline(int(entry.name))
        if not argv or not any(Path(item).name == BRIDGE_PROCESS_SCRIPT for item in argv):
            continue
        if (
            _option_values(argv, "--host") == [BRIDGE_HOST]
            and _option_values(argv, "--port") == [str(BRIDGE_PORT)]
            and _option_values(argv, "--device") == [BRIDGE_SERIAL_DEVICE]
            and _option_values(argv, "--expect-realpath") == [BRIDGE_SERIAL_DEVICE]
            and len(_option_values(argv, "--device-glob")) == 1
            and BRIDGE_SERIAL_GLOB_TOKEN in _option_values(argv, "--device-glob")[0]
        ):
            matches.append(int(entry.name))
    if len(matches) != 1:
        raise LiveError(f"expected exactly one uniquely bound A90 bridge, found {len(matches)}")
    return {
        "listener": {"host": BRIDGE_HOST, "port": BRIDGE_PORT},
        "serial_device": BRIDGE_SERIAL_DEVICE,
        "serial_identity_resolved": True,
        "bridge_process_script": BRIDGE_PROCESS_SCRIPT,
        "unique_process": True,
    }


def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Publish one artifact with O_EXCL/O_NOFOLLOW and an fsync."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise LiveError(f"refusing to clobber output {path}") from exc
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise LiveError(f"short write while publishing {path}")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor or "/")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise LiveError(f"output path contains a symlink: {current}")


def ensure_private_output(path: Path) -> Path:
    """Create a fresh 0700 directory below an evidence/private component."""

    requested = Path(path)
    if not requested.name or requested.name in {".", ".."}:
        raise LiveError("output directory must have a dedicated basename")
    lexical = requested if requested.is_absolute() else Path.cwd() / requested
    # Check the caller's spelling before resolve(); otherwise a symlinked
    # evidence/private parent could be silently accepted after resolution.
    _reject_symlink_components(lexical)
    resolved = lexical.resolve(strict=False)
    parts = resolved.parts
    indexes = [
        i for i in range(len(parts) - 1)
        if parts[i] == "evidence" and parts[i + 1] == "private"
    ]
    if not indexes:
        raise LiveError("output directory must remain below evidence/private")
    private_root = Path(*parts[: indexes[-1] + 2])
    _reject_symlink_components(private_root)
    private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.mkdir(resolved, 0o700)
    except FileExistsError as exc:
        raise LiveError(f"output directory already exists: {resolved}") from exc
    except OSError as exc:
        raise LiveError(f"cannot create private output directory: {resolved}") from exc
    os.chmod(resolved, 0o700)
    return resolved


def _frame_rc(frame: Frame, label: str) -> int:
    try:
        return int(frame.end["rc"], 0)
    except (KeyError, TypeError, ValueError) as exc:
        raise LiveError(f"{label} frame lacks an integer return code") from exc


def require_frame_ok(frame: Frame, label: str) -> None:
    rc = _frame_rc(frame, label)
    if rc != 0 or frame.end.get("status") != "ok":
        raise LiveError(
            f"{label} failed: rc={frame.end.get('rc')!r} "
            f"status={frame.end.get('status')!r}"
        )


def call(
    host: str,
    port: int,
    evidence_id: str,
    argv: tuple[str, ...],
    timeout: float,
    *,
    extended: bool = False,
    allow_error: bool = False,
) -> Frame:
    command = ExtendedCommand(evidence_id, argv) if extended else Command(evidence_id, argv)
    try:
        return exchange(host, port, command, timeout, allow_error=allow_error)
    except Exception as exc:
        raise LiveError(
            f"A90P1 command failed at {evidence_id}: {argv!r}: {exc}"
        ) from exc


def require_child_exit_zero(payload: bytes, label: str) -> None:
    matches = list(EXIT_RE.finditer(payload))
    if not matches:
        raise LiveError(f"{label} lacks a child exit receipt")
    code = int(matches[-1].group(1), 10)
    if code != 0:
        raise LiveError(f"{label} child exited {code}")


def parse_run_value(payload: bytes, label: str) -> str:
    require_child_exit_zero(payload, label)
    values: list[str] = []
    for line in payload.replace(b"\r\n", b"\n").splitlines():
        if RUN_PREFIX_RE.fullmatch(line) or EXIT_RE.fullmatch(line + b"\n"):
            continue
        try:
            values.append(line.decode("utf-8", errors="strict"))
        except UnicodeDecodeError as exc:
            raise LiveError(f"{label} returned non-UTF-8 data") from exc
    value = "\n".join(values).strip()
    if not value:
        raise LiveError(f"{label} returned no value")
    return value


def child_exit_code(payload: bytes) -> int | None:
    matches = list(EXIT_RE.finditer(payload))
    return int(matches[-1].group(1), 10) if matches else None


def child_pid(payload: bytes) -> int | None:
    match = RUN_PID_RE.search(payload.replace(b"\r\n", b"\n"))
    return int(match.group(1), 10) if match is not None else None


def prove_probe_completion(
    session: _Session,
    payload: bytes | None,
) -> dict[str, object]:
    """Prove a probe child ended, terminating it only after a transport timeout."""

    if payload is not None and child_exit_code(payload) is not None:
        return {
            "proved": True,
            "method": "child_exit_receipt",
            "pid": child_pid(payload),
            "errors": [],
        }
    pid = child_pid(payload or b"")
    if pid is None:
        return {
            "proved": False,
            "method": "UNPROVED_NO_CHILD_PID_OR_EXIT",
            "pid": None,
            "errors": ["probe transport supplied no cancellable child PID"],
        }
    errors: list[str] = []
    try:
        terminate = session.invoke(
            "probe_terminate",
            ("run", TOYBOX, "kill", "-TERM", str(pid)),
            allow_error=True,
        )
        require_frame_ok(terminate, "probe termination")
    except BaseException as exc:
        errors.append(f"terminate: {type(exc).__name__}: {exc}")
    for attempt in range(5):
        try:
            check = session.invoke(
                f"probe_termination_check_{attempt}",
                ("run", TOYBOX, "kill", "-0", str(pid)),
                allow_error=True,
            )
            require_frame_ok(check, f"probe termination check {attempt}")
            if child_exit_code(check.payload) not in {0, None}:
                return {
                    "proved": True,
                    "method": "kill_term_then_kill_zero_nonzero",
                    "pid": pid,
                    "errors": errors,
                }
        except BaseException as exc:
            errors.append(f"check{attempt}: {type(exc).__name__}: {exc}")
            break
        time.sleep(0.2)
    return {
        "proved": False,
        "method": "KILL_NOT_CONFIRMED",
        "pid": pid,
        "errors": errors or ["probe child remained alive after bounded termination checks"],
    }


def validate_target(version: bytes, cmdline: bytes) -> dict[str, object]:
    try:
        version_text = version.decode("utf-8", errors="strict")
        cmdline_text = cmdline.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise LiveError("target identity payload is not UTF-8") from exc
    version_lines = [line.strip() for line in version_text.splitlines() if line.strip()]
    runtime_lines = [line for line in version_lines if line.startswith("A90 Linux init ")]
    canonical_lines = [line for line in version_lines if line.startswith("version: ")]
    kernel_lines = [line for line in version_lines if line.startswith("kernel: ")]
    expected_runtime_line = f"{EXPECTED_VERSION} ({EXPECTED_RUNTIME_BUILD})"
    expected_canonical_line = f"version: {EXPECTED_RUNTIME} {EXPECTED_BUILD}"
    expected_kernel_line = f"kernel: {EXPECTED_KERNEL}"
    if runtime_lines != [expected_runtime_line]:
        raise LiveError("target version runtime identity is missing, conflicting, or duplicated")
    if canonical_lines != [expected_canonical_line]:
        raise LiveError("target version build identity is missing, conflicting, or duplicated")
    if kernel_lines != [expected_kernel_line]:
        raise LiveError("target version kernel identity is missing, conflicting, or duplicated")

    expected_by_key = {
        token.split("=", 1)[0]: token for token in EXPECTED_CMDLINE_TOKENS
    }
    seen_by_key: dict[str, str] = {}
    for token in cmdline_text.split():
        key = token.split("=", 1)[0]
        if key not in expected_by_key:
            continue
        previous = seen_by_key.get(key)
        if previous is not None:
            raise LiveError(f"target cmdline repeats identity key {key!r}")
        seen_by_key[key] = token
        if token != expected_by_key[key]:
            raise LiveError(f"target cmdline contains conflicting identity {key!r}")
    missing = sorted(set(expected_by_key) - set(seen_by_key))
    if missing:
        raise LiveError(f"target cmdline lacks exact identity key(s): {missing}")
    return {
        "model": EXPECTED_MODEL,
        "soc": EXPECTED_SOC,
        "runtime_version": EXPECTED_RUNTIME,
        "runtime_build": EXPECTED_RUNTIME_BUILD,
        "kernel": EXPECTED_KERNEL,
        "bootloader": EXPECTED_BOOTLOADER,
        "debug_level": "0x4f4c",
        "force_upload": "0x0",
        "dump_sink": "0x0",
    }


def make_envelope(binary: bytes) -> tuple[str, str, str]:
    return (
        "begin-base64 700 v018-alias-probe\n",
        base64.b64encode(binary).decode("ascii"),
        "\n====\n",
    )


def _parse_remote_hash(payload: bytes, label: str) -> str:
    require_child_exit_zero(payload, label)
    match = HASH_LINE_RE.search(payload.replace(b"\r\n", b"\n"))
    if match is None:
        raise LiveError(f"{label} output is malformed")
    path = match.group(2).decode("ascii", errors="strict")
    if path != REMOTE_BINARY:
        raise LiveError(f"{label} named an unexpected path: {path!r}")
    return match.group(1).decode("ascii")


def upload_binary(
    session: _Session,
    binary: bytes,
    timeout: float | None = None,
) -> dict[str, object]:
    """Upload one binary; the caller performs the fixed pre-clean first."""

    del timeout
    header, body, footer = make_envelope(binary)
    chunks = [
        body[offset : offset + MAX_LEGACY_CHUNK]
        for offset in range(0, len(body), MAX_LEGACY_CHUNK)
    ]
    header_frame = session.invoke(
        "envelope_header",
        ("appendfile", REMOTE_ENVELOPE, header),
        extended=True,
        allow_error=True,
    )
    require_frame_ok(header_frame, "envelope header")
    for index, chunk in enumerate(chunks):
        chunk_frame = session.invoke(
            f"payload_{index:04d}",
            ("appendfile", REMOTE_ENVELOPE, chunk),
            allow_error=True,
        )
        require_frame_ok(chunk_frame, f"envelope payload {index}")
    footer_frame = session.invoke(
        "envelope_footer",
        ("appendfile", REMOTE_ENVELOPE, footer),
        extended=True,
        allow_error=True,
    )
    require_frame_ok(footer_frame, "envelope footer")
    decode = session.invoke(
        "decode",
        ("run", TOYBOX, "uudecode", "-o", REMOTE_BINARY, REMOTE_ENVELOPE),
        allow_error=True,
    )
    require_frame_ok(decode, "uudecode")
    require_child_exit_zero(decode.payload, "uudecode")
    chmod = session.invoke(
        "chmod_binary",
        ("run", TOYBOX, "chmod", "700", REMOTE_BINARY),
        allow_error=True,
    )
    require_frame_ok(chmod, "binary chmod")
    require_child_exit_zero(chmod.payload, "binary chmod")
    remote_hash_frame = session.invoke(
        "remote_hash_before_run",
        ("run", TOYBOX, "sha256sum", REMOTE_BINARY),
        allow_error=True,
    )
    require_frame_ok(remote_hash_frame, "remote binary hash before run")
    remote_hash = _parse_remote_hash(
        remote_hash_frame.payload, "remote binary hash before run"
    )
    local_hash = sha256(binary)
    if remote_hash != local_hash:
        raise LiveError(f"remote binary hash differs: {remote_hash} != {local_hash}")
    return {
        "binary_size": len(binary),
        "binary_sha256": local_hash,
        "base64_bytes": len(body),
        "chunk_bytes": MAX_LEGACY_CHUNK,
        "chunk_count": len(chunks),
        "remote_path": REMOTE_BINARY,
        "remote_sha256_verified": True,
        "remote_before_run_sha256": remote_hash,
    }


def validate_probe_payload(payload: bytes) -> tuple[bytes, list[dict[str, object]]]:
    """Check protocol framing and fixed context; do not classify alias results."""

    require_child_exit_zero(payload, "probe")
    normalized = payload.replace(b"\r\n", b"\n")
    lines = normalized.splitlines()
    if (
        len(lines) < 3
        or RUN_PREFIX_RE.fullmatch(lines[0]) is None
        or EXIT_RE.fullmatch(lines[-1]) is None
    ):
        raise LiveError("probe transport framing is not exact")
    json_lines = lines[1:-1]
    if any(not line for line in json_lines):
        raise LiveError("probe JSONL contains a blank record")
    jsonl = b"\n".join(json_lines) + b"\n"
    try:
        records = marker_analysis.parse(jsonl, "live probe")
    except marker_analysis.MarkerError as exc:
        raise LiveError(f"probe JSONL contract failed: {exc}") from exc
    context = records[0]
    expected: Mapping[str, object] = {
        "heap": EXPECTED_HEAP,
        "mib": EXPECTED_MIB,
        "anchors": EXPECTED_ANCHORS,
        "trials": EXPECTED_TRIALS,
        "seed": EXPECTED_SEED,
        "low_bit": marker_analysis.CACHE_LINE_SHIFT,
        "top_bit": marker_analysis.TOP_BIT,
        "algorithm": "pmplease_alg2",
        "mapping": "write_combine",
    }
    for key, wanted in expected.items():
        if key not in context:
            raise LiveError(f"probe context lacks {key!r}")
        actual = context[key]
        if key == "seed":
            if not isinstance(actual, str) or actual.lower() != EXPECTED_SEED:
                raise LiveError(f"probe context seed differs: {actual!r}")
        elif actual != wanted:
            raise LiveError(f"probe context {key!r} differs: {actual!r}")
    if context.get("ion_node") != REMOTE_ION:
        raise LiveError(f"probe context ion node differs: {context.get('ion_node')!r}")
    return jsonl, records


def parse_selftest(payload: bytes) -> dict[str, int]:
    match = SELFTEST_RE.search(payload.replace(b"\r\n", b"\n"))
    if match is None:
        raise LiveError("final selftest lacks the exact summary")
    values = {key: int(value) for key, value in match.groupdict().items()}
    if values["fail"] != 0:
        raise LiveError(f"final selftest reports failures: {values}")
    return values


def _hash_descriptor(
    path: Path,
    label: str,
    data: bytes | None = None,
) -> dict[str, object]:
    if data is None:
        data = read_stable(path, label)
    return {
        "basename": Path(path).name,
        "size_bytes": len(data),
        "sha256": sha256(data),
    }


def _frame_descriptor(frame: Frame | None) -> dict[str, object] | None:
    if frame is None:
        return None
    return {
        "begin": dict(frame.begin),
        "end": dict(frame.end),
        "payload_size": len(frame.payload),
        "payload_sha256": sha256(frame.payload),
        "transcript_size": len(frame.transcript),
        "transcript_sha256": sha256(frame.transcript),
    }


def _remote_test_absence(session: _Session, evidence_id: str, path: str) -> None:
    frame = session.invoke(
        evidence_id,
        ("run", TOYBOX, "test", "!", "-e", path),
        allow_error=True,
    )
    require_frame_ok(frame, evidence_id)
    require_child_exit_zero(frame.payload, evidence_id)


def _record_error(errors: list[str], label: str, exc: BaseException) -> None:
    errors.append(f"{label}: {type(exc).__name__}: {exc}")


def expected_command_ids(chunk_count: int) -> list[str]:
    if not isinstance(chunk_count, int) or isinstance(chunk_count, bool) or chunk_count < 1:
        raise LiveError("upload chunk count is invalid")
    return [
        "version", "cmdline", "ion_dev", "preclean", "envelope_header",
        *[f"payload_{index:04d}" for index in range(chunk_count)],
        "envelope_footer", "decode", "chmod_binary", "remote_hash_before_run",
        "ion_node_create", "ion_node_chmod", "probe", "remote_hash_after_run",
        "cleanup_node", "cleanup_files", "absence_node", "absence_envelope",
        "absence_binary", "final_version", "final_cmdline", "final_selftest",
    ]


def validate_command_log(
    commands: Sequence[Mapping[str, object]],
    *,
    chunk_count: int,
    require_exact: bool = True,
) -> None:
    if not isinstance(commands, Sequence) or isinstance(commands, (str, bytes)):
        raise LiveError("command receipt is not a sequence")
    expected = expected_command_ids(chunk_count)
    actual = [entry.get("evidence_id") for entry in commands if isinstance(entry, Mapping)]
    if require_exact and actual != expected:
        raise LiveError(f"command receipt order differs: expected {expected}, got {actual}")
    seen: set[str] = set()
    for index, entry in enumerate(commands):
        if not isinstance(entry, Mapping):
            raise LiveError(f"command receipt entry {index} is not an object")
        evidence_id = entry.get("evidence_id")
        argv = entry.get("argv")
        if not isinstance(evidence_id, str) or evidence_id in seen:
            raise LiveError(f"command receipt entry {index} has a duplicate/invalid id")
        seen.add(evidence_id)
        if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
            raise LiveError(f"command receipt entry {index} argv is invalid")
        if "error" in entry:
            if require_exact:
                raise LiveError(f"command receipt entry {evidence_id} retained an error")
            continue
        begin = entry.get("begin")
        end = entry.get("end")
        if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
            raise LiveError(f"command receipt entry {evidence_id} lacks frame metadata")
        if begin.get("cmd") != argv[0] or end.get("cmd") != argv[0]:
            raise LiveError(f"command receipt entry {evidence_id} command differs from argv")
        if begin.get("seq") != end.get("seq"):
            raise LiveError(f"command receipt entry {evidence_id} sequence differs")
        transcript_size = entry.get("transcript_size")
        if not isinstance(transcript_size, int) or isinstance(transcript_size, bool) or transcript_size <= 0:
            raise LiveError(f"command receipt entry {evidence_id} transcript size is invalid")


def _validate_args(args: argparse.Namespace) -> None:
    if args.host != BRIDGE_HOST:
        raise LiveError("V018 runner only accepts bridge host 127.0.0.1")
    if args.port != BRIDGE_PORT:
        raise LiveError("V018 runner only accepts bridge port 54321")
    if not isinstance(args.timeout, (int, float)) or not 0 < args.timeout <= 300:
        raise LiveError("timeout must be within 0 < timeout <= 300 seconds")
    if not isinstance(args.probe_timeout, (int, float)) or not 0 < args.probe_timeout <= 1800:
        raise LiveError("probe timeout must be within 0 < timeout <= 1800 seconds")
    total_timeout = getattr(args, "total_timeout", DEFAULT_TOTAL_TIMEOUT)
    if not isinstance(total_timeout, (int, float)) or not 0 < total_timeout <= 3600:
        raise LiveError("total timeout must be within 0 < timeout <= 3600 seconds")
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise LiveError("experiment ID has invalid characters")
    for name in ("binary", "source", "output_dir", "build_receipt"):
        if not isinstance(getattr(args, name), Path):
            setattr(args, name, Path(getattr(args, name)))
    expected_source = (REPO_ROOT / "tools" / EXPECTED_PROBE_SOURCE_BASENAME).resolve()
    if args.source.resolve() != expected_source:
        raise LiveError("V018 source must be the exact checked-in probe source")
    if args.binary.name != EXPECTED_PROBE_BINARY_BASENAME:
        raise LiveError("V018 binary basename must be v018-alias-probe")


def run(args: argparse.Namespace) -> Path:
    """Run one fixed acquisition; return the fresh private output directory."""

    _validate_args(args)
    output_dir = ensure_private_output(args.output_dir)
    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    binary = read_stable(args.binary, "probe binary")
    if not binary:
        raise LiveError("probe binary is empty")
    source = read_stable(args.source, "probe source")
    build_receipt_bytes = read_stable(args.build_receipt, "build receipt")
    runner = read_stable(RUNNER_SCRIPT_PATH, "runner script")
    bridge = read_stable(BRIDGE_SCRIPT_PATH, "bridge script")
    artifacts = {
        "source": _hash_descriptor(args.source, "probe source", source),
        "binary": _hash_descriptor(args.binary, "probe binary", binary),
        "runner": _hash_descriptor(RUNNER_SCRIPT_PATH, "runner script", runner),
        "bridge_script": _hash_descriptor(BRIDGE_SCRIPT_PATH, "bridge script", bridge),
        "build_receipt": _hash_descriptor(
            args.build_receipt, "build receipt", build_receipt_bytes
        ),
    }
    build = validate_build_receipt(
        build_receipt_bytes,
        source=artifacts["source"],
        binary=artifacts["binary"],
    )

    session = _Session(
        BRIDGE_HOST,
        BRIDGE_PORT,
        float(args.timeout),
        deadline=time.monotonic() + float(getattr(args, "total_timeout", DEFAULT_TOTAL_TIMEOUT)),
    )
    target: dict[str, object] | None = None
    target_bound = False
    node_created = False
    probe_payload: bytes | None = None
    probe_jsonl: bytes | None = None
    probe_records: list[dict[str, object]] | None = None
    version_frame: Frame | None = None
    cmdline_frame: Frame | None = None
    upload: dict[str, object] | None = None
    remote_before: str | None = None
    remote_after: str | None = None
    ion_identity: str | None = None
    bridge_binding: dict[str, object] | None = None
    probe_completion: dict[str, object] = {
        "proved": False,
        "method": "NOT_RUN",
        "pid": None,
        "errors": [],
    }
    cleanup: dict[str, object] = {
        "attempted": False,
        "node_removed": False,
        "files_removed": False,
        "absence_proved": False,
        "errors": [],
    }
    final_health: dict[str, object] = {
        "attempted": False,
        "ok": False,
        "errors": [],
    }
    failures: list[str] = []
    primary_error: BaseException | None = None

    def fail(label: str, exc: BaseException) -> None:
        nonlocal primary_error
        if primary_error is None:
            primary_error = exc
        _record_error(failures, label, exc)

    try:
        bridge_binding = validate_bridge_binding()
        version_frame = session.invoke("version", ("version",))
        cmdline_frame = session.invoke(
            "cmdline", ("run", TOYBOX, "cat", "/proc/cmdline")
        )
        require_child_exit_zero(cmdline_frame.payload, "cmdline")
        target = validate_target(version_frame.payload, cmdline_frame.payload)
        target_bound = True

        ion_frame = session.invoke(
            "ion_dev", ("run", TOYBOX, "cat", ION_DEV_PATH)
        )
        ion_identity = parse_run_value(ion_frame.payload, "ion_dev")
        if ion_identity != EXPECTED_ION_DEV:
            raise LiveError(f"unexpected live ION misc identity: {ion_identity!r}")

        preclean = session.invoke(
            "preclean",
            ("run", TOYBOX, "rm", "-f", REMOTE_ENVELOPE, REMOTE_BINARY, REMOTE_ION),
            allow_error=True,
        )
        require_frame_ok(preclean, "preclean")
        require_child_exit_zero(preclean.payload, "preclean")
        upload = upload_binary(session, binary)
        remote_before = str(upload["remote_before_run_sha256"])

        node = session.invoke(
            "ion_node_create",
            ("run", TOYBOX, "mknod", REMOTE_ION, "c", "10", "94"),
            allow_error=True,
        )
        require_frame_ok(node, "ION node create")
        require_child_exit_zero(node.payload, "ION node create")
        node_created = True
        node_chmod = session.invoke(
            "ion_node_chmod",
            ("run", TOYBOX, "chmod", "600", REMOTE_ION),
            allow_error=True,
        )
        require_frame_ok(node_chmod, "ION node chmod")
        require_child_exit_zero(node_chmod.payload, "ION node chmod")

        probe = session.invoke(
            "probe", PROBE_ARGV, float(args.probe_timeout), allow_error=True
        )
        probe_payload = probe.payload
        probe_error: BaseException | None = None
        try:
            require_frame_ok(probe, "probe A90P1 frame")
            require_child_exit_zero(probe_payload, "probe")
            probe_jsonl, probe_records = validate_probe_payload(probe_payload)
        except BaseException as exc:
            # The hash-after-run check still runs whenever a probe frame was
            # received, including a child/protocol failure.
            probe_error = exc

        probe_completion = prove_probe_completion(session, probe_payload)
        if probe_error is not None and not probe_completion["proved"]:
            raise LiveError(
                f"probe failed without a bounded termination proof: {probe_completion}"
            ) from probe_error

        after = session.invoke(
            "remote_hash_after_run",
            ("run", TOYBOX, "sha256sum", REMOTE_BINARY),
            allow_error=True,
        )
        require_frame_ok(after, "remote binary hash after run")
        remote_after = _parse_remote_hash(
            after.payload, "remote binary hash after run"
        )
        if remote_after != str(upload["binary_sha256"]):
            raise LiveError(
                f"remote binary changed during probe: {remote_after} != "
                f"{upload['binary_sha256']}"
            )
        if probe_error is not None:
            raise probe_error
    except BaseException as exc:
        fail("acquisition", exc)

    # Once the exact target is bound, cleanup and health are mandatory.  Before
    # binding, sending commands to a drifted target would violate fail-closed
    # identity isolation, so only the local incident is retained.
    if target_bound:
        cleanup["attempted"] = True
        try:
            node_cleanup = session.invoke(
                "cleanup_node",
                ("run", TOYBOX, "rm", "-f", REMOTE_ION),
                allow_error=True,
            )
            require_frame_ok(node_cleanup, "ION node cleanup")
            require_child_exit_zero(node_cleanup.payload, "ION node cleanup")
            cleanup["node_removed"] = True
        except BaseException as exc:
            _record_error(cleanup["errors"], "cleanup_node", exc)
            fail("cleanup_node", exc)
        try:
            files_cleanup = session.invoke(
                "cleanup_files",
                ("run", TOYBOX, "rm", "-f", REMOTE_ENVELOPE, REMOTE_BINARY),
                allow_error=True,
            )
            require_frame_ok(files_cleanup, "file cleanup")
            require_child_exit_zero(files_cleanup.payload, "file cleanup")
            cleanup["files_removed"] = True
        except BaseException as exc:
            _record_error(cleanup["errors"], "cleanup_files", exc)
            fail("cleanup_files", exc)
        absence_ok = True
        for evidence_id, path in (
            ("absence_node", REMOTE_ION),
            ("absence_envelope", REMOTE_ENVELOPE),
            ("absence_binary", REMOTE_BINARY),
        ):
            try:
                _remote_test_absence(session, evidence_id, path)
            except BaseException as exc:
                absence_ok = False
                _record_error(cleanup["errors"], evidence_id, exc)
                fail(evidence_id, exc)
        cleanup["absence_proved"] = absence_ok

        final_health["attempted"] = True
        try:
            final_version = session.invoke("final_version", ("version",))
            final_cmdline = session.invoke(
                "final_cmdline", ("run", TOYBOX, "cat", "/proc/cmdline")
            )
            require_child_exit_zero(final_cmdline.payload, "final cmdline")
            final_target = validate_target(
                final_version.payload, final_cmdline.payload
            )
            selftest_frame = session.invoke(
                "final_selftest", ("selftest", "status")
            )
            require_frame_ok(selftest_frame, "final selftest")
            selftest = parse_selftest(selftest_frame.payload)
            final_health.update(
                {"ok": True, "target": final_target, "selftest": selftest}
            )
        except BaseException as exc:
            final_health["errors"].append(
                f"{type(exc).__name__}: {exc}"
            )
            fail("final_health", exc)

    # Raw/transcript publication happens before the receipt; the receipt is
    # therefore only eligible after cleanup and final-health attempts finish.
    if probe_payload is not None:
        try:
            write_new(
                output_dir / RAW_PAYLOAD_BASENAME,
                probe_payload or b"",
                0o600,
            )
            if probe_jsonl is not None:
                write_new(output_dir / RAW_BASENAME, probe_jsonl, 0o600)
        except BaseException as exc:
            fail("raw_publication", exc)
    try:
        write_new(
            output_dir / TRANSCRIPT_BASENAME,
            b"".join(session.transcript_parts),
            0o600,
        )
    except BaseException as exc:
        fail("transcript_publication", exc)

    completed = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    raw_meta: dict[str, object] | None = None
    raw_payload_meta: dict[str, object] | None = None
    transcript_meta: dict[str, object] | None = None
    for name, key in (
        (RAW_BASENAME, "raw"),
        (RAW_PAYLOAD_BASENAME, "raw_payload"),
        (TRANSCRIPT_BASENAME, "transcript"),
    ):
        path = output_dir / name
        try:
            output_info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(output_info.st_mode):
            fail(f"{key}_hash", LiveError(f"{key} output is a symlink"))
            continue
        try:
            data = read_stable(path, key)
            metadata = {
                "basename": name,
                "size_bytes": len(data),
                "sha256": sha256(data),
            }
            if key == "raw":
                raw_meta = metadata
            elif key == "raw_payload":
                raw_payload_meta = metadata
            else:
                transcript_meta = metadata
        except BaseException as exc:
            fail(f"{key}_hash", exc)

    if upload is not None:
        try:
            validate_command_log(
                session.commands,
                chunk_count=int(upload["chunk_count"]),
                require_exact=(primary_error is None),
            )
        except BaseException as exc:
            fail("command_receipt", exc)

    success = (
        primary_error is None
        and target_bound
        and probe_records is not None
        and raw_meta is not None
        and raw_payload_meta is not None
        and transcript_meta is not None
        and upload is not None
        and remote_before is not None
        and remote_after == remote_before == str(upload["binary_sha256"])
        and bool(cleanup["node_removed"])
        and bool(cleanup["files_removed"])
        and bool(cleanup["absence_proved"])
        and bool(final_health["ok"])
        and not failures
    )
    receipt: dict[str, object] = {
        "schema": SCHEMA,
        "status": "PASS" if success else "INCIDENT",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_bound": target_bound,
        "target": target,
        "target_frames": {
            "version": _frame_descriptor(version_frame),
            "cmdline": _frame_descriptor(cmdline_frame),
        },
        "bridge": {"host": BRIDGE_HOST, "port": BRIDGE_PORT},
        "bridge_binding": bridge_binding,
        "command_argv": list(PROBE_ARGV),
        "probe_argv": list(PROBE_CLI_ARGS),
        "probe": {
            "schema": PROBE_SCHEMA,
            "records": len(probe_records) if probe_records is not None else 0,
            "child_pid": probe_completion.get("pid"),
            "child_exit_proved": probe_completion.get("proved") is True,
            "raw": raw_meta,
            "payload": raw_payload_meta,
        },
        "probe_completion": probe_completion,
        "artifacts": artifacts,
        "source": artifacts["source"],
        "binary": artifacts["binary"],
        "runner": artifacts["runner"],
        "bridge_script": artifacts["bridge_script"],
        "build_receipt": artifacts["build_receipt"],
        "build": build,
        "upload": upload,
        "remote_binary": {
            "path": REMOTE_BINARY,
            "before_run_sha256": remote_before,
            "after_run_sha256": remote_after,
            "unchanged": remote_before is not None and remote_before == remote_after,
        },
        "ion_device": {
            "sysfs_path": ION_DEV_PATH,
            "sysfs_identity": ion_identity,
            "expected_identity": EXPECTED_ION_DEV,
            "temporary_node": REMOTE_ION,
            "node_created": node_created,
        },
        "cleanup": cleanup,
        "final_health": final_health,
        "transcript": transcript_meta,
        "commands": session.commands,
        "command_sequence_validated": bool(
            upload is not None and primary_error is None
        ),
        "failures": failures,
        "claims": {
            "interpretation": "DEFERRED_TO_HOST_ANALYZER",
            "device_alias_result": "NOT_CLAIMED" if not success else "RAW_ONLY",
        },
    }
    try:
        write_new(output_dir / RECEIPT_BASENAME, json_bytes(receipt), 0o600)
    except BaseException as exc:
        fail("receipt_publication", exc)
        raise LiveError(f"V018 acquisition failed: {failures}") from exc
    if not success:
        raise LiveError(f"V018 acquisition incident: {failures}")
    return output_dir


def collect(args: argparse.Namespace) -> Path:
    return run(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument(
        "--source", type=Path, default=Path("tools/a90_alias_marker_probe.c")
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--host", default=BRIDGE_HOST)
    parser.add_argument("--port", type=int, default=BRIDGE_PORT)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--probe-timeout", type=float, default=300.0)
    parser.add_argument("--total-timeout", type=float, default=DEFAULT_TOTAL_TIMEOUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        output = run(args)
    except LiveError as exc:
        print(f"verification-018: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
