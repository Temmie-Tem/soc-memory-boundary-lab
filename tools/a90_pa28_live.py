#!/usr/bin/env python3
"""Run the fixed Verification 022R PA28 probe through the A90P1 bridge.

This runner is deliberately narrower than a general command wrapper.  It
accepts one already-built, receipt-pinned AArch64 probe and one fresh private
output directory.  The remote command, temporary paths, target identity,
ION major/minor, and all probe arguments are constants in this module.  A
successful receipt proves only that this bounded normal-RAM acquisition was
performed and cleaned up; interpretation remains the host analyzer's job.

The module is import-safe: importing it performs no compiler invocation,
socket connection, process launch, or device discovery.  Tests replace the
transport and bridge-binding functions with mocks.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
from dataclasses import dataclass, field
from typing import Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.a90_acm_snapshot import Command, Frame, parse_fields, parse_last_frame


SCHEMA = "a90_pa28_live_v1"
PUBLIC_SCHEMA = "a90_pa28_live_public_v1"
PROBE_SCHEMA = "a90_pa28_probe_v022r_v1"
BUILD_SCHEMA = "a90_pa28_build_v1"

# The bridge is an operator-started A90P1 process.  These values are checked
# both in argv and in the local serial identity before the first command.
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 54321
BRIDGE_PROCESS_SCRIPT = "serial_tcp_bridge.py"
BRIDGE_PROCESS_SCRIPT_PATH = Path(
    "/home/temmie/dev/android-native-init-lab/workspace/public/src/scripts/"
    "revalidation/serial_tcp_bridge.py"
)
EXPECTED_BRIDGE_SCRIPT_BASENAME = "serial_tcp_bridge.py"
EXPECTED_BRIDGE_SCRIPT_SIZE = 21170
EXPECTED_BRIDGE_SCRIPT_SHA256 = (
    "febfb95f408f62f516c2e4f6c25f5da61535f7b75366c3f73cc47bfd91fba077"
)
EXPECTED_COMPILER_TRIPLE = "aarch64-linux-gnu"
EXPECTED_COMPILER_VERSION = (
    "aarch64-linux-gnu-gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0"
)
BRIDGE_SERIAL_DEVICE = "/dev/ttyACM0"
BRIDGE_SERIAL_ID = "/dev/serial/by-id/usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00"
BRIDGE_SERIAL_GLOB_TOKEN = "usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00"

EXPECTED_VERSION = "A90 Linux init 0.9.285"
EXPECTED_BUILD = "build=v2321-usb-clean-identity-rodata"
EXPECTED_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
EXPECTED_RUNTIME = "0.9.285"
EXPECTED_RUNTIME_BUILD = "v2321-usb-clean-identity-rodata"
EXPECTED_MODEL = "SM-A908N"
EXPECTED_SOC = "SM8150"
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
REMOTE_ENVELOPE = f"{REMOTE_ROOT}/v022r-pa28-probe.b64u"
REMOTE_BINARY = f"{REMOTE_ROOT}/v022r-pa28-probe"
REMOTE_ION = f"{REMOTE_ROOT}/v022r-ion"
ION_DEV_PATH = "/sys/class/misc/ion/dev"
TOYBOX = "/bin/toybox"
EXPECTED_ION_DEV = "10:94"
EXPECTED_SELFTEST_PASS = 11
EXPECTED_SELFTEST_WARN = 1
EXPECTED_SELFTEST_ENTRIES = 12

EXPECTED_HEAP = "camera_preview"
EXPECTED_MIB = 320
EXPECTED_REPETITIONS = 201
EXPECTED_PAIRS = 256
EXPECTED_CPU = 7
EXPECTED_CNTFRQ = 19_200_000
EXPECTED_WARMUPS = 17
EXPECTED_OFFSET_MODE = "spread"
EXPECTED_ORDER = "alternating"
EXPECTED_BARRIER = "dsb_ld"
EXPECTED_DIVISOR = "kept_times_two"
EXPECTED_BASE = 0xC2000000
EXPECTED_BASE_TEXT = "0xc2000000"

# This is the complete, fixed 022R identification invocation.  The two
# controls are intentionally repeated at the end; there is no mode switch or
# caller-provided difference list.
FIXED_DIFFERENCES: tuple[str, ...] = (
    "0x16000",
    "0x2000",
    "0x10002000",
    "0x10004000",
    "0x10006000",
    "0x10008000",
    "0x1000a000",
    "0x1000c000",
    "0x1000e000",
    "0x16000",
    "0x2000",
)
PROBE_CLI_ARGS: tuple[str, ...] = (
    EXPECTED_HEAP,
    str(EXPECTED_MIB),
    str(EXPECTED_REPETITIONS),
    str(EXPECTED_PAIRS),
    str(EXPECTED_CPU),
    EXPECTED_OFFSET_MODE,
    EXPECTED_BASE_TEXT,
    REMOTE_ION,
    *FIXED_DIFFERENCES,
)
PROBE_ARGV: tuple[str, ...] = ("run", REMOTE_BINARY, *PROBE_CLI_ARGS)

# Pins are for the checked-in repaired source and the reproducible build made
# with the repository's documented AArch64 command.  Tests may replace these
# constants with fixture pins, but production execution cannot provide a
# merely self-consistent receipt.
EXPECTED_PROBE_SOURCE_BASENAME = "a90_pa28_probe_v022r.c"
EXPECTED_PROBE_BINARY_BASENAME = "v022r-pa28-probe"
EXPECTED_PROBE_SOURCE_SIZE = 27415
EXPECTED_PROBE_SOURCE_SHA256 = (
    "d66e8930fdf8456cb99ee6d4e6d9b8386d3f645d3a902091c39b814b3f73b315"
)
EXPECTED_PROBE_BINARY_SIZE = 776408
EXPECTED_PROBE_BINARY_SHA256 = (
    "ed826cc75dee1eafad3b1b1ea4b0b779147364a330201e284b9e24c92adf1b92"
)

BRIDGE_SCRIPT_PATH = BRIDGE_PROCESS_SCRIPT_PATH
RUNNER_SCRIPT_PATH = Path(__file__).resolve()

MAX_LEGACY_CHUNK = 3500
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
DEFAULT_PROBE_TIMEOUT = 900.0
DEFAULT_CLEANUP_HEALTH_RESERVE = 225.0
# The default must leave substantial bounded time for the fixed upload and
# pre-dispatch identity checks in addition to the probe and post-run reserve.
DEFAULT_TOTAL_TIMEOUT = 1800.0
MIN_PRE_DISPATCH_BUDGET = 300.0
MIN_CLEANUP_HEALTH_RESERVE = 5.0
MAX_CLEANUP_HEALTH_RESERVE = 300.0
MAX_CANCEL_TIMEOUT = 30.0
CANCEL_CONNECT_ATTEMPTS = 3
CANCEL_BUSY_TEXT = b"[bridge] busy: another client is active; retry later\r\n"
# serial_tcp_bridge.py selects its sockets once per second.  A reconnect must
# observe a quiet/busy client for longer than that tick before writing raw
# input, otherwise a stale client can be mistaken for the active shell.
BRIDGE_CLIENT_OBSERVATION_WINDOW = 1.25
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
EXIT_RE = re.compile(rb"(?:^|\r?\n)\[exit ([0-9]+)\](?:\r?\n|$)")
RUN_PREFIX_RE = re.compile(rb"run: pid=[0-9]+, q/Ctrl-C cancels")
RUN_PID_RE = re.compile(
    rb"(?:^|\r?\n)run: pid=([0-9]+), q/Ctrl-C cancels(?:\r?\n|$)"
)
BEGIN_RE = re.compile(
    rb"(?:^|\r?\n)A90P1 BEGIN (?P<fields>[^\r\n]+)\r?\n"
)
HASH_LINE_RE = re.compile(rb"(?m)^([0-9a-f]{64})  (\S+)\s*$")
SELFTEST_RE = re.compile(
    rb"(?m)^selftest:\s+pass=(?P<passed>[0-9]+)\s+"
    rb"warn=(?P<warn>[0-9]+)\s+fail=(?P<fail>[0-9]+)\s+"
    rb"duration=(?P<duration>[0-9]+)ms\s+entries=(?P<entries>[0-9]+)\s*$"
)

RAW_BASENAME = "pa28-identification.jsonl"
RAW_PAYLOAD_BASENAME = "probe-output.bin"
TRANSCRIPT_BASENAME = "transcript.bin"
BUILD_RECEIPT_COPY_BASENAME = "build-receipt.json"
RECEIPT_BASENAME = "receipt.json"


class LiveError(RuntimeError):
    """Any failure of the 022R acquisition/evidence contract."""


@dataclass(frozen=True)
class PartialEvidence:
    """Transport bytes/metadata available when a command did not complete."""

    payload: bytes | None = None
    transcript: bytes | None = None
    begin: Mapping[str, object] | None = None
    end: Mapping[str, object] | None = None


class TransportFailure(LiveError):
    """A command transport failure carrying any bytes exposed by the transport."""

    def __init__(self, message: str, *, partial: PartialEvidence | None = None) -> None:
        super().__init__(message)
        self.partial = partial


@dataclass(frozen=True)
class ExtendedCommand:
    """Newline-safe A90P1 command used for base64 envelope delimiters."""

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


def _partial_evidence_from(value: BaseException) -> PartialEvidence | None:
    """Extract optional partial evidence from a transport/mock exception.

    The stock bridge may expose no bytes when its socket read times out.  A
    test double or a future transport can attach ``partial_frame``,
    ``partial_payload``, or ``partial_transcript``; preserving those fields
    here keeps the timeout path fail-closed without pretending completion.
    """

    if isinstance(value, TransportFailure):
        return value.partial
    frame = getattr(value, "partial_frame", None)
    if frame is None:
        frame = getattr(value, "frame", None)
    payload = getattr(value, "partial_payload", None)
    transcript = getattr(value, "partial_transcript", None)
    begin = getattr(value, "partial_begin", None)
    end = getattr(value, "partial_end", None)
    if isinstance(frame, Frame):
        payload = frame.payload if payload is None else payload
        transcript = frame.transcript if transcript is None else transcript
        begin = frame.begin if begin is None else begin
        end = frame.end if end is None else end
    if payload is not None and not isinstance(payload, bytes):
        payload = None
    if transcript is not None and not isinstance(transcript, bytes):
        transcript = None
    if begin is not None and not isinstance(begin, Mapping):
        begin = None
    if end is not None and not isinstance(end, Mapping):
        end = None
    if payload is None and transcript is None and begin is None and end is None:
        return None
    return PartialEvidence(payload, transcript, begin, end)


@dataclass
class _Session:
    host: str
    port: int
    timeout: float
    deadline: float | None = None
    total_deadline: float | None = None
    transcript_parts: list[bytes] = field(default_factory=list)
    commands: list[dict[str, object]] = field(default_factory=list)
    partial_evidence: dict[str, PartialEvidence] = field(default_factory=dict)
    prompt_ready: bool = False
    last_call_started: bool = False

    def partial_payload(self, evidence_id: str) -> bytes | None:
        partial = self.partial_evidence.get(evidence_id)
        return partial.payload if partial is not None else None

    def partial_transcript(self, evidence_id: str) -> bytes | None:
        partial = self.partial_evidence.get(evidence_id)
        return partial.transcript if partial is not None else None

    def invoke(
        self,
        evidence_id: str,
        argv: tuple[str, ...],
        timeout: float | None = None,
        *,
        extended: bool = False,
        allow_error: bool = False,
    ) -> Frame:
        command_started = utc_now()
        monotonic_started = time.monotonic()
        frame: Frame | None = None
        call_started = False
        self.last_call_started = False
        try:
            now = time.monotonic()
            if self.deadline is not None and now >= self.deadline:
                raise LiveError("022R total acquisition deadline expired")
            command_timeout = self.timeout if timeout is None else timeout
            if self.deadline is not None:
                command_timeout = min(command_timeout, self.deadline - now)
                if command_timeout <= 0:
                    raise LiveError("022R command has no remaining deadline")
            call_started = True
            self.last_call_started = True
            frame = call(
                self.host,
                self.port,
                evidence_id,
                argv,
                command_timeout,
                extended=extended,
                allow_error=allow_error,
            )
            # A returned Frame means the bridge reader saw the original
            # terminal END and prompt.  Validation errors below do not erase
            # that prompt proof; a transport exception does.
            self.prompt_ready = True
            if (
                len(frame.transcript) > MAX_FRAME_BYTES
                or len(frame.payload) > MAX_PAYLOAD_BYTES
            ):
                raise LiveError(f"{evidence_id} frame exceeds bounded evidence size")
            if frame.begin.get("cmd") != argv[0] or frame.end.get("cmd") != argv[0]:
                raise LiveError(f"{evidence_id} frame command does not match argv")
            if frame.begin.get("seq") != frame.end.get("seq"):
                raise LiveError(f"{evidence_id} frame sequence differs at END")
            if not allow_error:
                require_frame_ok(frame, evidence_id)
        except BaseException as exc:
            if call_started and frame is None:
                self.prompt_ready = False
            partial = _partial_evidence_from(exc)
            if partial is not None:
                partial_over_limit = (
                    (partial.payload is not None and len(partial.payload) > MAX_PAYLOAD_BYTES)
                    or (
                        partial.transcript is not None
                        and len(partial.transcript) > MAX_FRAME_BYTES
                    )
                )
                if partial_over_limit:
                    partial = PartialEvidence(
                        payload=(
                            partial.payload
                            if partial.payload is not None
                            and len(partial.payload) <= MAX_PAYLOAD_BYTES
                            else None
                        ),
                        transcript=(
                            partial.transcript
                            if partial.transcript is not None
                            and len(partial.transcript) <= MAX_FRAME_BYTES
                            else None
                        ),
                        begin=partial.begin,
                        end=partial.end,
                    )
                self.partial_evidence[evidence_id] = partial
                if partial.transcript:
                    self.transcript_parts.append(
                        f"\n===== {evidence_id} PARTIAL =====\n".encode("ascii")
                        + partial.transcript
                    )
            partial_record: dict[str, object] = {}
            if partial is not None:
                partial_record = {
                    "partial_over_limit": partial_over_limit,
                    "partial_payload_size": (
                        len(partial.payload) if partial.payload is not None else None
                    ),
                    "partial_payload_sha256": (
                        sha256(partial.payload) if partial.payload is not None else None
                    ),
                    "partial_transcript_size": (
                        len(partial.transcript)
                        if partial.transcript is not None else None
                    ),
                    "partial_transcript_sha256": (
                        sha256(partial.transcript)
                        if partial.transcript is not None else None
                    ),
                    "partial_pid": (
                        child_pid(partial.payload)
                        if partial.payload is not None else None
                    ),
                }
                if partial.begin is not None:
                    partial_record["partial_begin"] = dict(partial.begin)
                if partial.end is not None:
                    partial_record["partial_end"] = dict(partial.end)
            self.commands.append(
                {
                    "evidence_id": evidence_id,
                    "argv": list(argv),
                    "extended": extended,
                    "started_utc": command_started,
                    "completed_utc": utc_now(),
                    "duration_monotonic_s": max(0.0, time.monotonic() - monotonic_started),
                    "child_exit_code": (
                        child_exit_code(frame.payload)
                        if frame is not None else None
                    ),
                    "error": f"{type(exc).__name__}: {exc}",
                    **partial_record,
                }
            )
            raise
        command_completed = utc_now()
        exit_code = child_exit_code(frame.payload) if argv[0] == "run" else None
        self.transcript_parts.append(
            f"\n===== {evidence_id} =====\n".encode("ascii") + frame.transcript
        )
        self.commands.append(
            {
                "evidence_id": evidence_id,
                "argv": list(argv),
                "extended": extended,
                "started_utc": command_started,
                "completed_utc": command_completed,
                "duration_monotonic_s": max(0.0, time.monotonic() - monotonic_started),
                "child_exit_code": exit_code if argv[0] == "run" else "NOT_APPLICABLE",
                "begin": dict(frame.begin),
                "end": dict(frame.end),
                "transcript_sha256": sha256(frame.transcript),
                "transcript_size": len(frame.transcript),
            }
        )
        return frame


def utc_now() -> str:
    """Return an RFC3339 UTC timestamp with sub-second precision."""

    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def cleanup_health_reserve(probe_timeout: float) -> float:
    """Return the separately reserved post-dispatch cleanup/health window."""

    return max(
        MIN_CLEANUP_HEALTH_RESERVE,
        min(MAX_CLEANUP_HEALTH_RESERVE, float(probe_timeout) * 0.25),
    )


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
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LiveError(f"{label} cannot be opened without following links") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise LiveError(f"{label} is not a regular file: {path}")
        if info.st_size < 0 or info.st_size > MAX_INPUT_BYTES:
            raise LiveError(f"{label} exceeds bounded input size")
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def read_stable(path: Path, label: str) -> bytes:
    """Read one regular input without links and prove it stayed unchanged."""

    path = Path(path)
    _reject_symlink_components(path)
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
        before.st_nlink,
    )
    after_key = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
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
    if not isinstance(value, Mapping) or set(value) != {
        "basename", "size_bytes", "sha256"
    }:
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


def _valid_compiler_command(value: object) -> bool:
    if not isinstance(value, list) or not value or any(
        not isinstance(item, str) or not item for item in value
    ):
        return False
    executable = Path(value[0]).name
    try:
        output_index = value.index("-o")
    except ValueError:
        return False
    return (
        executable == "aarch64-linux-gnu-gcc"
        and value[1:output_index]
        == ["-O2", "-static", "-Wall", "-Wextra", "-Werror"]
        and output_index + 2 < len(value)
        and Path(value[output_index + 1]).name == EXPECTED_PROBE_BINARY_BASENAME
        and len(value) == output_index + 3
        and value[output_index + 2]
        == f"tools/{EXPECTED_PROBE_SOURCE_BASENAME}"
    )


def validate_build_receipt(
    data: bytes,
    *,
    source: Mapping[str, object],
    binary: Mapping[str, object],
    label: str = "build receipt",
) -> dict[str, object]:
    """Require the exact source/binary and a reproducible static build proof."""

    receipt = _json_document(data, label)
    required = {
        "schema", "source", "binary", "compiler", "reproducible_byte_identical"
    }
    if set(receipt) != required or receipt.get("schema") != BUILD_SCHEMA:
        raise LiveError(f"{label} top-level fields/schema differ")
    receipt_source = _artifact_descriptor(receipt.get("source"), f"{label} source")
    receipt_binary = _artifact_descriptor(receipt.get("binary"), f"{label} binary")
    if receipt_source != dict(source) or receipt_binary != dict(binary):
        raise LiveError(f"{label} does not bind exact source and binary")
    if receipt_source["basename"] != EXPECTED_PROBE_SOURCE_BASENAME:
        raise LiveError(f"{label} source basename differs")
    if receipt_binary["basename"] != EXPECTED_PROBE_BINARY_BASENAME:
        raise LiveError(f"{label} binary basename differs")
    if (
        source.get("basename") != EXPECTED_PROBE_SOURCE_BASENAME
        or source.get("size_bytes") != EXPECTED_PROBE_SOURCE_SIZE
        or source.get("sha256") != EXPECTED_PROBE_SOURCE_SHA256
        or binary.get("basename") != EXPECTED_PROBE_BINARY_BASENAME
        or binary.get("size_bytes") != EXPECTED_PROBE_BINARY_SIZE
        or binary.get("sha256") != EXPECTED_PROBE_BINARY_SHA256
    ):
        raise LiveError("022R source/binary pins are unset or differ from final build")
    compiler = receipt.get("compiler")
    if not isinstance(compiler, Mapping) or set(compiler) != {
        "triple", "version", "command", "static"
    }:
        raise LiveError(f"{label} compiler identity fields differ")
    command = compiler.get("command")
    valid_command = _valid_compiler_command(command)
    if (
        compiler.get("triple") != EXPECTED_COMPILER_TRIPLE
        or compiler.get("version") != EXPECTED_COMPILER_VERSION
        or not valid_command
        or compiler.get("static") is not True
        or receipt.get("reproducible_byte_identical") is not True
    ):
        raise LiveError(f"{label} compiler/build reproducibility proof is incomplete")
    return {
        "schema": BUILD_SCHEMA,
        "compiler_triple": EXPECTED_COMPILER_TRIPLE,
        "compiler_version": EXPECTED_COMPILER_VERSION,
        "compiler_command": list(command),
        "static": True,
        "reproducible_byte_identical": True,
    }


def _proc_cmdline(pid: int) -> list[str] | None:
    path = Path("/proc") / str(pid) / "cmdline"
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
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
    values: list[str] = []
    for index, value in enumerate(argv[:-1]):
        if value == option:
            values.append(argv[index + 1])
    return values


def _bridge_listener_owned(pid: int) -> bool:
    """Prove that *pid* owns an IPv4 listener on the fixed bridge port."""

    tcp_path = Path("/proc") / str(pid) / "net" / "tcp"
    fd_path = Path("/proc") / str(pid) / "fd"
    try:
        lines = tcp_path.read_text(encoding="ascii").splitlines()
        fd_entries = list(fd_path.iterdir())
    except (OSError, UnicodeDecodeError):
        return False
    listener_inodes: set[str] = set()
    wanted_port = f"{BRIDGE_PORT:04X}"
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            address, port = fields[1].split(":", 1)
        except ValueError:
            continue
        if address.upper() == "0100007F" and port.upper() == wanted_port and fields[3] == "0A":
            listener_inodes.add(fields[9])
    if not listener_inodes:
        return False
    for fd_entry in fd_entries:
        try:
            target = os.readlink(fd_entry)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match is not None and match.group(1) in listener_inodes:
            return True
    return False


def _bridge_script_descriptor() -> dict[str, object]:
    data = read_stable(BRIDGE_SCRIPT_PATH, "serial_tcp_bridge.py")
    descriptor = _hash_descriptor(BRIDGE_SCRIPT_PATH, "serial_tcp_bridge.py", data)
    if (
        descriptor["basename"] != EXPECTED_BRIDGE_SCRIPT_BASENAME
        or descriptor["size_bytes"] != EXPECTED_BRIDGE_SCRIPT_SIZE
        or descriptor["sha256"] != EXPECTED_BRIDGE_SCRIPT_SHA256
    ):
        raise LiveError("actual serial_tcp_bridge.py bytes do not match the pinned bridge")
    return descriptor


def validate_bridge_binding() -> dict[str, object]:
    """Bind the one explicit A90 serial bridge serving the fixed listener."""

    script_descriptor = _bridge_script_descriptor()
    expected_script_path = BRIDGE_PROCESS_SCRIPT_PATH.resolve(strict=False)
    try:
        resolved_id = os.path.realpath(BRIDGE_SERIAL_ID)
        if resolved_id != BRIDGE_SERIAL_DEVICE:
            raise LiveError(
                "configured A90 serial identity does not resolve to /dev/ttyACM0"
            )
        info = os.stat(BRIDGE_SERIAL_DEVICE)
    except OSError as exc:
        raise LiveError("configured A90 serial device is unavailable") from exc
    if not stat.S_ISCHR(info.st_mode):
        raise LiveError("configured A90 serial path is not a character device")

    matches: list[dict[str, object]] = []
    try:
        proc_entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise LiveError("cannot enumerate /proc for bridge binding") from exc
    for entry in proc_entries:
        if not entry.name.isdigit():
            continue
        argv = _proc_cmdline(int(entry.name))
        if not argv:
            # Processes can disappear (or expose an empty cmdline) between
            # /proc enumeration and inspection.  They are not candidates for
            # an exact bridge-owner binding.
            continue
        script_args = [
            item for item in argv if Path(item).name == BRIDGE_PROCESS_SCRIPT
        ]
        if not script_args or not any(
            Path(item).resolve(strict=False) == expected_script_path
            for item in script_args
        ):
            continue
        host_values = _option_values(argv, "--host")
        port_values = _option_values(argv, "--port")
        device_values = _option_values(argv, "--device")
        expect_values = _option_values(argv, "--expect-realpath")
        glob_values = _option_values(argv, "--device-glob")
        if (
            host_values == [BRIDGE_HOST]
            and port_values == [str(BRIDGE_PORT)]
            and device_values == [BRIDGE_SERIAL_DEVICE]
            and expect_values == [BRIDGE_SERIAL_DEVICE]
            and len(glob_values) == 1
            and BRIDGE_SERIAL_GLOB_TOKEN in glob_values[0]
            and _bridge_listener_owned(int(entry.name))
        ):
            matches.append({"pid": int(entry.name), "argv": argv})
    if len(matches) != 1:
        raise LiveError(f"expected exactly one uniquely bound A90 bridge, found {len(matches)}")
    process = matches[0]
    return {
        "listener": {"host": BRIDGE_HOST, "port": BRIDGE_PORT},
        "serial_device": BRIDGE_SERIAL_DEVICE,
        "serial_identity": BRIDGE_SERIAL_ID,
        "serial_realpath": resolved_id,
        "serial_stat": {
            "st_dev": info.st_dev,
            "st_ino": info.st_ino,
            "st_rdev": info.st_rdev,
            "mode": stat.S_IMODE(info.st_mode),
            "character_device": True,
        },
        "validated_utc": utc_now(),
        "process_pid": process["pid"],
        "process_argv": process["argv"],
        "bridge_process_script": BRIDGE_PROCESS_SCRIPT,
        "bridge_process_script_path": str(BRIDGE_PROCESS_SCRIPT_PATH),
        "bridge_process_script_descriptor": script_descriptor,
        "unique_process": True,
    }


def revalidate_bridge_binding(initial: Mapping[str, object]) -> dict[str, object]:
    """Recheck the exact bridge PID/argv/script/device immediately pre-probe."""

    if not isinstance(initial, Mapping):
        raise LiveError("initial bridge binding is not an object")
    current = validate_bridge_binding()
    required_same = (
        "listener",
        "serial_device",
        "serial_identity",
        "serial_realpath",
        "serial_stat",
        "process_pid",
        "process_argv",
        "bridge_process_script",
        "bridge_process_script_path",
        "bridge_process_script_descriptor",
    )
    for key in required_same:
        if key not in initial or key not in current or initial[key] != current[key]:
            raise LiveError(f"bridge binding drifted before probe at {key}")
    if current.get("unique_process") is not True:
        raise LiveError("bridge binding is no longer unique before probe")
    return current


def _reject_symlink_components(path: Path) -> None:
    """Reject symlinked components before resolving a local output path."""

    lexical = path if path.is_absolute() else Path.cwd() / path
    current = Path(lexical.anchor or "/")
    parts = lexical.parts[1:] if lexical.is_absolute() else lexical.parts
    for part in parts:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise LiveError(f"cannot inspect output component {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise LiveError(f"output path contains a symlink: {current}")


def ensure_private_output(path: Path) -> Path:
    """Create one fresh 0700 directory below an ``evidence/private`` root."""

    requested = Path(path)
    if not requested.name or requested.name in {".", ".."}:
        raise LiveError("output directory must have a dedicated basename")
    lexical = requested if requested.is_absolute() else Path.cwd() / requested
    _reject_symlink_components(lexical)
    resolved = lexical.resolve(strict=False)
    parts = resolved.parts
    indexes = [
        index
        for index in range(len(parts) - 1)
        if parts[index] == "evidence" and parts[index + 1] == "private"
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


def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write one fresh regular file with no-follow/no-clobber semantics."""

    path = Path(path)
    _reject_symlink_components(path)
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
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise LiveError(f"short write while publishing {path}")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


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


def _partial_from_transcript(transcript: bytes) -> PartialEvidence:
    """Build bounded best-effort frame evidence from an incomplete transcript."""

    bounded = transcript[:MAX_FRAME_BYTES]
    begin: Mapping[str, object] | None = None
    payload: bytes | None = None
    matches = list(BEGIN_RE.finditer(bounded))
    if matches:
        match = matches[-1]
        try:
            begin = parse_fields(match.group("fields"))
        except (UnicodeDecodeError, ValueError):
            begin = None
        body = bounded[match.end() :]
        if len(body) <= MAX_PAYLOAD_BYTES:
            payload = body
    return PartialEvidence(
        payload=payload,
        transcript=bounded,
        begin=begin,
    )


def _read_local_transcript(sock: socket.socket, timeout: float) -> bytes:
    """Read one A90P1 transcript while retaining bounded bytes on failure."""

    deadline = time.monotonic() + timeout
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportFailure(
                "timed out waiting for a complete A90P1 frame and prompt",
                partial=_partial_from_transcript(bytes(data)),
            )
        # Keep recv bounded below the command deadline so a socket timeout
        # cannot consume the reserved post-probe cleanup/health window.
        sock.settimeout(min(0.2, max(0.001, remaining)))
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            continue
        if not chunk:
            raise TransportFailure(
                "bridge closed before a complete A90P1 frame and prompt",
                partial=_partial_from_transcript(bytes(data)),
            )
        if len(data) + len(chunk) > MAX_FRAME_BYTES:
            room = max(0, MAX_FRAME_BYTES - len(data))
            if room:
                data.extend(chunk[:room])
            raise TransportFailure(
                "A90P1 transcript exceeds bounded evidence size",
                partial=_partial_from_transcript(bytes(data)),
            )
        data.extend(chunk)
        end_at = data.rfind(b"A90P1 END ")
        if end_at >= 0 and (
            b"\na90:/#" in data[end_at:]
            or b"\ra90:/#" in data[end_at:]
        ):
            return bytes(data)


def _local_exchange(
    host: str,
    port: int,
    command: Command | ExtendedCommand,
    timeout: float,
    *,
    allow_error: bool = False,
) -> Frame:
    """Exchange one frame without delegating partial-byte handling elsewhere."""

    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise TransportFailure("A90P1 command timeout is invalid")
    timeout_value = float(timeout)
    if not math.isfinite(timeout_value) or timeout_value <= 0:
        raise TransportFailure("A90P1 command timeout is not positive")
    operation_deadline = time.monotonic() + timeout_value
    transcript = b""
    try:
        connect_timeout = min(timeout_value, 3.0)
        with socket.create_connection(
            (host, port), timeout=connect_timeout
        ) as sock:
            remaining = operation_deadline - time.monotonic()
            if remaining <= 0:
                raise TransportFailure(
                    "A90P1 command deadline expired before send",
                    partial=_partial_from_transcript(transcript),
                )
            sock.settimeout(min(0.2, max(0.001, remaining)))
            sock.sendall(b"\n" + command.wire)
            remaining = operation_deadline - time.monotonic()
            if remaining <= 0:
                raise TransportFailure(
                    "A90P1 command deadline expired while waiting for frame",
                    partial=_partial_from_transcript(transcript),
                )
            transcript = _read_local_transcript(sock, remaining)
    except TransportFailure:
        raise
    except Exception as exc:
        raise TransportFailure(
            f"A90P1 socket exchange failed: {exc}",
            partial=_partial_from_transcript(transcript),
        ) from exc

    try:
        frame = parse_last_frame(transcript, command.argv[0])
    except Exception as exc:
        raise TransportFailure(
            f"A90P1 frame parsing failed: {exc}",
            partial=_partial_from_transcript(transcript),
        ) from exc
    try:
        frame_rc = _frame_rc(frame, "A90P1 command")
    except LiveError as exc:
        raise TransportFailure(
            f"A90P1 frame return code is invalid: {exc}",
            partial=PartialEvidence(
                payload=frame.payload,
                transcript=frame.transcript,
                begin=frame.begin,
                end=frame.end,
            ),
        ) from exc
    if not allow_error and (frame_rc != 0 or frame.end.get("status") != "ok"):
        raise TransportFailure(
            f"A90P1 command failed: rc={frame.end.get('rc')!r} "
            f"status={frame.end.get('status')!r}",
            partial=PartialEvidence(
                payload=frame.payload,
                transcript=frame.transcript,
                begin=frame.begin,
                end=frame.end,
            ),
        )
    return frame


# Keep a narrow patch seam for host tests and callers that previously replaced
# the imported exchange helper.  Production calls use the local implementation
# above, which is the only implementation that preserves partial socket bytes.
exchange = _local_exchange


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
        raise TransportFailure(
            f"A90P1 command failed at {evidence_id}: {argv!r}: {exc}",
            partial=_partial_evidence_from(exc),
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


def validate_target(version: bytes, cmdline: bytes) -> dict[str, object]:
    """Require one exact V2321 runtime/build/kernel and cmdline identity."""

    try:
        version_text = version.decode("utf-8", errors="strict")
        cmdline_text = cmdline.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise LiveError("target identity payload is not UTF-8") from exc
    version_lines = [line.strip() for line in version_text.splitlines() if line.strip()]
    runtime_lines = [line for line in version_lines if line.startswith("A90 Linux init ")]
    canonical_lines = [line for line in version_lines if line.startswith("version: ")]
    kernel_lines = [line for line in version_lines if line.startswith("kernel: ")]
    if runtime_lines != [f"{EXPECTED_VERSION} ({EXPECTED_RUNTIME_BUILD})"]:
        raise LiveError("target runtime version is missing, conflicting, or duplicated")
    if canonical_lines != [f"version: {EXPECTED_RUNTIME} {EXPECTED_BUILD}"]:
        raise LiveError("target canonical build is missing, conflicting, or duplicated")
    if kernel_lines != [f"kernel: {EXPECTED_KERNEL}"]:
        raise LiveError("target kernel identity is missing, conflicting, or duplicated")

    expected_by_key = {token.split("=", 1)[0]: token for token in EXPECTED_CMDLINE_TOKENS}
    seen_by_key: dict[str, str] = {}
    for token in cmdline_text.split():
        key = token.split("=", 1)[0]
        if key not in expected_by_key:
            continue
        if key in seen_by_key:
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
        f"begin-base64 700 {EXPECTED_PROBE_BINARY_BASENAME}\n",
        base64.b64encode(binary).decode("ascii"),
        "\n====\n",
    )


def _parse_remote_hash(payload: bytes, label: str) -> str:
    require_child_exit_zero(payload, label)
    matches = list(HASH_LINE_RE.finditer(payload.replace(b"\r\n", b"\n")))
    if len(matches) != 1:
        raise LiveError(f"{label} output is malformed")
    match = matches[0]
    path = match.group(2).decode("ascii", errors="strict")
    if path != REMOTE_BINARY:
        raise LiveError(f"{label} named an unexpected path: {path!r}")
    return match.group(1).decode("ascii")


def upload_binary(
    session: _Session,
    binary: bytes,
    timeout: float | None = None,
    *,
    lifecycle: dict[str, object] | None = None,
) -> dict[str, object]:
    """Upload one pinned binary through one fixed envelope."""

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
    if lifecycle is not None:
        lifecycle["upload_completed_utc"] = utc_now()
        lifecycle["remote_hash_before_started_utc"] = utc_now()
    remote_hash_frame = session.invoke(
        "remote_hash_before_run",
        ("run", TOYBOX, "sha256sum", REMOTE_BINARY),
        allow_error=True,
    )
    require_frame_ok(remote_hash_frame, "remote binary hash before run")
    remote_hash = _parse_remote_hash(
        remote_hash_frame.payload, "remote binary hash before run"
    )
    if lifecycle is not None:
        lifecycle["remote_hash_before_completed_utc"] = utc_now()
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


HEX_RE = re.compile(r"0x[0-9a-f]+\Z")
RECORD_FIELDS: dict[str, frozenset[str]] = {
    "context": frozenset(
        {
            "schema", "type", "cpu", "cntfrq", "heap", "mib", "repetitions",
            "pairs", "warmups", "order", "barrier", "divisor", "offset_mode",
            "declared_base",
        }
    ),
    "ion_heap": frozenset(
        {"schema", "type", "name", "heap_type", "heap_id"}
    ),
    "pa_provenance": frozenset(
        {
            "schema", "type", "source", "pages", "present", "nonzero_pfn",
            "first_pfn", "last_pfn", "contiguous", "status",
        }
    ),
    "pair": frozenset(
        {"schema", "type", "value", "offset", "pa_a", "pa_b", "pa_xor", "delta"}
    ),
    "difference": frozenset(
        {
            "schema", "type", "value", "pairs", "rejected_range",
            "rejected_carry", "p10", "median", "p90",
        }
    ),
    "cleanup": frozenset(
        {
            "schema", "type", "attempted", "released", "ion_fd_closed",
            "allocation_fd_closed", "map_unmapped", "eviction_unmapped",
            "heaps_freed", "sample_buffers_freed", "status",
        }
    ),
}
EXPECTED_DIFFERENCE_VALUES = tuple(int(item, 16) for item in FIXED_DIFFERENCES)
EXPECTED_PAGE_COUNT = (EXPECTED_MIB * 1024 * 1024) // 4096


def _canonical_hex(value: object, label: str) -> int:
    if not isinstance(value, str) or HEX_RE.fullmatch(value) is None:
        raise LiveError(f"{label} is not lowercase hexadecimal")
    parsed = int(value, 16)
    if value != hex(parsed):
        raise LiveError(f"{label} is not canonically formatted")
    return parsed


def _integer(value: object, label: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LiveError(f"{label} is not an integer")
    if minimum is not None and value < minimum:
        raise LiveError(f"{label} is below {minimum}")
    return value


def _strict_record_shape(record: Mapping[str, object], label: str) -> None:
    kind = record.get("type")
    if not isinstance(kind, str) or kind not in RECORD_FIELDS:
        raise LiveError(f"{label} has unsupported record type")
    if set(record) != RECORD_FIELDS[kind]:
        raise LiveError(f"{label} fields differ for {kind}")
    if record.get("schema") != PROBE_SCHEMA:
        raise LiveError(f"{label} has a foreign schema")


def _decode_json_line(line: bytes, label: str) -> dict[str, object]:
    if not line or line.strip() != line:
        raise LiveError(f"{label} is blank or has surrounding whitespace")
    try:
        value = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=lambda items: _json_pairs(items, label),
            parse_constant=lambda value: _json_nonfinite(value, label),
        )
    except LiveError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LiveError(f"{label} is malformed UTF-8/JSON") from exc
    if not isinstance(value, dict):
        raise LiveError(f"{label} is not an object")
    return value


def _json_pairs(items: list[tuple[str, object]], label: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise LiveError(f"{label} repeats key {key!r}")
        result[key] = value
    return result


def _json_nonfinite(value: str, label: str) -> object:
    raise LiveError(f"{label} contains non-finite JSON number {value!r}")


def validate_probe_records(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Validate the complete fixed 022R JSONL order and arithmetic.

    The probe intentionally emits variable numbers of pair rows because the
    allocation can start at a different offset.  The fixed command and every
    summary's accounting remain invariant, so pair count is checked against
    each summary rather than replacing that count with a guessed constant.
    """

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise LiveError("probe records are not a sequence")
    if not records:
        raise LiveError("probe emitted no JSON records")
    normalized: list[Mapping[str, object]] = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, Mapping):
            raise LiveError(f"probe record {index} is not an object")
        _strict_record_shape(record, f"probe record {index}")
        normalized.append(record)

    contexts = [record for record in normalized if record.get("type") == "context"]
    heaps = [record for record in normalized if record.get("type") == "ion_heap"]
    provenance = [
        record for record in normalized if record.get("type") == "pa_provenance"
    ]
    if len(contexts) != 1 or len(heaps) != 1 or len(provenance) != 1:
        raise LiveError("probe requires exactly one context, heap, and pagemap record")

    context = contexts[0]
    expected_context: dict[str, object] = {
        "cpu": EXPECTED_CPU,
        "cntfrq": EXPECTED_CNTFRQ,
        "heap": EXPECTED_HEAP,
        "mib": EXPECTED_MIB,
        "repetitions": EXPECTED_REPETITIONS,
        "pairs": EXPECTED_PAIRS,
        "warmups": EXPECTED_WARMUPS,
        "order": EXPECTED_ORDER,
        "barrier": EXPECTED_BARRIER,
        "divisor": EXPECTED_DIVISOR,
        "offset_mode": EXPECTED_OFFSET_MODE,
        "declared_base": EXPECTED_BASE_TEXT,
    }
    for key, wanted in expected_context.items():
        actual = context.get(key)
        if key in {"cpu", "cntfrq", "mib", "repetitions", "pairs", "warmups"}:
            _integer(actual, f"context.{key}")
        if actual != wanted:
            raise LiveError(f"context {key!r} differs: {actual!r}")

    heap = heaps[0]
    if (
        heap.get("name") != EXPECTED_HEAP
        or _integer(heap.get("heap_type"), "ion_heap.heap_type") != 10
        or _integer(heap.get("heap_id"), "ion_heap.heap_id") != 30
    ):
        raise LiveError("ION heap identity differs from camera_preview type 10/id 30")

    pagemap = provenance[0]
    if (
        pagemap.get("source") != "pagemap"
        or pagemap.get("status") != "BLIND"
        or _integer(pagemap.get("pages"), "pa_provenance.pages") != EXPECTED_PAGE_COUNT
        or _integer(pagemap.get("present"), "pa_provenance.present") != 0
        or _integer(pagemap.get("nonzero_pfn"), "pa_provenance.nonzero_pfn") != 0
        or pagemap.get("first_pfn") != "0x0"
        or pagemap.get("last_pfn") != "0x0"
        or pagemap.get("contiguous") is not True
    ):
        raise LiveError("pagemap provenance is not the fixed blind result")

    # Metadata has one fixed prefix.  Pair rows must be immediately followed
    # by the matching summary.  Groups are tracked by occurrence, rather than
    # a value-keyed dictionary, because the two controls intentionally repeat.
    if [record["type"] for record in normalized[:3]] != [
        "context", "ion_heap", "pa_provenance"
    ]:
        raise LiveError("probe metadata prefix is not in fixed order")
    groups: list[dict[str, object]] = []
    cleanup_record: dict[str, object] | None = None
    current_deltas: list[int] = []
    expected_group_index = 0
    for index, record in enumerate(normalized[3:], 3):
        kind = record["type"]
        if expected_group_index >= len(EXPECTED_DIFFERENCE_VALUES):
            if kind != "cleanup" or index != len(normalized) - 1:
                raise LiveError("probe emitted records after fixed difference groups")
            cleanup_record = dict(record)
            break
        expected_value = EXPECTED_DIFFERENCE_VALUES[expected_group_index]
        if kind == "pair":
            value = _canonical_hex(record.get("value"), f"pair {index}.value")
            if value != expected_value:
                raise LiveError(
                    f"pair {index} interleaves or reorders difference groups"
                )
            offset = _canonical_hex(record.get("offset"), f"pair {index}.offset")
            pa_a = _canonical_hex(record.get("pa_a"), f"pair {index}.pa_a")
            pa_b = _canonical_hex(record.get("pa_b"), f"pair {index}.pa_b")
            pa_xor = _canonical_hex(record.get("pa_xor"), f"pair {index}.pa_xor")
            delta = _integer(record.get("delta"), f"pair {index}.delta")
            if delta < -(1 << 63) or delta > (1 << 63) - 1:
                raise LiveError(f"pair {index}.delta is outside signed 64-bit range")
            if offset % 4096 or offset + 4096 > EXPECTED_MIB * 1024 * 1024:
                raise LiveError(f"pair {index} offset is outside allocation")
            other_offset = offset ^ value
            if other_offset + 4096 > EXPECTED_MIB * 1024 * 1024:
                raise LiveError(f"pair {index} counterpart offset is outside allocation")
            expected_pa_a = EXPECTED_BASE + offset
            expected_pa_b = EXPECTED_BASE + other_offset
            if pa_a != expected_pa_a or pa_b != expected_pa_b:
                raise LiveError(f"pair {index} physical addresses do not match base+offset")
            if pa_xor != (pa_a ^ pa_b) or (pa_a ^ pa_b) != value:
                raise LiveError(f"pair {index} physical XOR is inconsistent")
            current_deltas.append(delta)
        elif kind == "difference":
            value = _canonical_hex(record.get("value"), f"summary {index}.value")
            if value != expected_value:
                raise LiveError("probe summary order differs from fixed invocation")
            pairs = _integer(
                record.get("pairs"),
                f"difference {expected_group_index}.pairs",
                minimum=1,
            )
            rejected_range = _integer(
                record.get("rejected_range"),
                f"difference {expected_group_index}.rejected_range",
                minimum=0,
            )
            rejected_carry = _integer(
                record.get("rejected_carry"),
                f"difference {expected_group_index}.rejected_carry",
                minimum=0,
            )
            p10 = _integer(record.get("p10"), f"difference {expected_group_index}.p10")
            median = _integer(
                record.get("median"), f"difference {expected_group_index}.median"
            )
            p90 = _integer(record.get("p90"), f"difference {expected_group_index}.p90")
            if pairs > EXPECTED_PAIRS or pairs + rejected_range + rejected_carry != EXPECTED_PAIRS:
                raise LiveError(
                    f"difference {expected_group_index} rejected-pair accounting is invalid"
                )
            if len(current_deltas) != pairs:
                raise LiveError(
                    f"difference {expected_group_index} pair count does not match rows"
                )
            ordered = sorted(current_deltas)
            trim = len(ordered) // 10
            expected_percentiles = (
                ordered[trim],
                ordered[len(ordered) // 2],
                ordered[len(ordered) - 1 - trim],
            )
            if (p10, median, p90) != expected_percentiles:
                raise LiveError(
                    f"difference {expected_group_index} percentiles do not match "
                    "the probe's exact sorted-index rule"
                )
            groups.append(
                {
                    "occurrence": expected_group_index,
                    "value": hex(value),
                    "pairs": pairs,
                    "rejected_range": rejected_range,
                    "rejected_carry": rejected_carry,
                    "p10": p10,
                    "median": median,
                    "p90": p90,
                }
            )
            current_deltas = []
            expected_group_index += 1
        elif kind == "cleanup":
            raise LiveError("probe cleanup record is not terminal")
        else:
            raise LiveError(f"probe record {index} has unsupported ordering")
    if cleanup_record is None:
        raise LiveError("probe lacks terminal cleanup record")
    if (
        cleanup_record.get("attempted") is not True
        or cleanup_record.get("released") is not True
        or cleanup_record.get("ion_fd_closed") is not True
        or cleanup_record.get("allocation_fd_closed") is not True
        or cleanup_record.get("map_unmapped") is not True
        or cleanup_record.get("eviction_unmapped") is not True
        or cleanup_record.get("heaps_freed") is not True
        or cleanup_record.get("sample_buffers_freed") is not True
        or cleanup_record.get("status") != "PASS"
    ):
        raise LiveError("probe terminal cleanup record is incomplete")
    if current_deltas or expected_group_index != len(EXPECTED_DIFFERENCE_VALUES):
        raise LiveError("probe has unclosed pair groups")
    return {
        "context": dict(context),
        "ion_heap": dict(heap),
        "pagemap": dict(pagemap),
        "cleanup": cleanup_record,
        "difference_values": [group["value"] for group in groups],
        "difference_groups": groups,
        "record_count": len(normalized),
    }


def validate_probe_payload(payload: bytes) -> tuple[bytes, list[dict[str, object]]]:
    """Require exact A90P1 child framing and validate its JSONL body."""

    require_child_exit_zero(payload, "probe")
    normalized = payload.replace(b"\r\n", b"\n")
    lines = normalized.splitlines()
    if (
        len(lines) < 5
        or RUN_PREFIX_RE.fullmatch(lines[0]) is None
        or EXIT_RE.fullmatch(lines[-1]) is None
    ):
        raise LiveError("probe transport framing is not exact")
    json_lines = lines[1:-1]
    if any(not line for line in json_lines):
        raise LiveError("probe JSONL contains a blank record")
    records = [_decode_json_line(line, f"probe JSONL record {index}")
               for index, line in enumerate(json_lines, 1)]
    validate_probe_records(records)
    return b"\n".join(json_lines) + b"\n", records


# Alternate names are intentionally small and stable for host-side callers.
parse_probe_payload = validate_probe_payload


def child_exit_code(payload: bytes) -> int | None:
    matches = list(EXIT_RE.finditer(payload))
    return int(matches[-1].group(1), 10) if matches else None


def child_pid(payload: bytes) -> int | None:
    match = RUN_PID_RE.search(payload.replace(b"\r\n", b"\n"))
    return int(match.group(1), 10) if match is not None else None


def prove_probe_completion(
    session: _Session,
    payload: bytes | None,
    *,
    expected_binding: Mapping[str, object] | None = None,
    timeout: float | None = None,
) -> dict[str, object]:
    """Prove probe termination without issuing a second framed command.

    ``run /bin/toybox ...`` is a blocking shell operation in the native
    runtime.  While it is active, another ``cmdv1`` line cannot be dispatched;
    the runtime's documented cancellation path is a raw Ctrl-C on the console
    stream.  A timed-out probe therefore gets one fresh loopback connection
    carrying only ``0x03``.  The remainder of the original frame is joined to
    the retained prefix and must contain the original BEGIN/END pair, the
    cancellation text, the matching child PID, and the returned prompt before
    any later framed cleanup command is allowed.
    """

    partial = session.partial_evidence.get("probe")
    evidence = payload
    if evidence is None:
        evidence = session.partial_transcript("probe")
    is_partial = partial is not None and evidence in {
        partial.payload,
        partial.transcript,
    }
    if evidence is not None and not is_partial and child_exit_code(evidence) is not None:
        return {
            "proved": True,
            "method": "child_exit_receipt",
            "pid": child_pid(evidence),
            "child_exit_code": child_exit_code(evidence),
            "channel_ready": True,
            "errors": [],
            "cancel": None,
        }
    cancel_evidence = session.partial_transcript("probe") or evidence
    return cancel_probe_raw(
        session,
        cancel_evidence,
        expected_binding=expected_binding,
        timeout=timeout,
    )


def _observe_cancel_connection(
    sock: socket.socket,
    deadline: float,
) -> str:
    """Observe one reconnect long enough to catch the bridge busy greeting."""

    window = max(0.001, float(BRIDGE_CLIENT_OBSERVATION_WINDOW))
    requested_until = time.monotonic() + window
    observe_until = min(deadline, requested_until)
    observed = b""
    while True:
        remaining = observe_until - time.monotonic()
        if remaining <= 0:
            if observed and CANCEL_BUSY_TEXT.startswith(observed):
                return "busy"
            if observed:
                return "unexpected"
            # A quiet connection is only safe to classify after the complete
            # source-backed observation window.  If the cancel deadline ends
            # sooner, do not send a byte into an unclassified connection.
            if deadline < requested_until:
                return "deadline"
            return "quiet"
        sock.settimeout(min(0.05, max(0.001, remaining)))
        try:
            chunk = sock.recv(len(CANCEL_BUSY_TEXT), socket.MSG_PEEK)
        except socket.timeout:
            continue
        if not chunk:
            return "closed"
        observed = chunk
        if observed.startswith(CANCEL_BUSY_TEXT):
            return "busy"
        if not CANCEL_BUSY_TEXT.startswith(observed):
            return "unexpected"


def cancel_probe_raw(
    session: _Session,
    partial_transcript: bytes | None,
    *,
    expected_binding: Mapping[str, object] | None = None,
    timeout: float | None = None,
) -> dict[str, object]:
    """Send one raw Ctrl-C and collect the original probe's terminal frame.

    The current bridge serializes clients and the native shell blocks while a
    ``run`` child is active.  At most one cancellation byte is sent.  Before
    that byte, each bounded connection attempt revalidates the exact final
    bridge binding and recognizes the bridge's explicit busy greeting.  Once
    the byte is sent, this function never reconnects or retries it.
    """

    original = partial_transcript
    if original is None:
        original = session.partial_transcript("probe")
    original = original or b""
    begin_matches = list(BEGIN_RE.finditer(original))
    original_begin: Mapping[str, object] | None = None
    if begin_matches:
        try:
            original_begin = parse_fields(begin_matches[-1].group("fields"))
        except (UnicodeDecodeError, ValueError):
            original_begin = None
    pid = child_pid(original)
    errors: list[str] = []
    cancel_byte = b"\x03"
    started = utc_now()
    remainder = b""
    sent = False
    sent_utc: str | None = None
    timeout_value = session.timeout if timeout is None else float(timeout)
    if not math.isfinite(timeout_value) or timeout_value <= 0:
        timeout_value = max(0.001, session.timeout)
    timeout_value = min(MAX_CANCEL_TIMEOUT, timeout_value)
    if session.total_deadline is not None:
        timeout_value = min(
            timeout_value,
            max(0.0, session.total_deadline - time.monotonic()),
        )
    attempts: list[dict[str, object]] = []
    event: dict[str, object] = {
        "method": "raw_ctrl_c_reconnect",
        "byte_hex": cancel_byte.hex(),
        "send_size": len(cancel_byte),
        "send_sha256": sha256(cancel_byte),
        "started_utc": started,
        "sent_utc": None,
        "completed_utc": None,
        "sent": False,
        "remainder_size": 0,
        "remainder_sha256": sha256(b""),
        "combined_size": len(original),
        "combined_sha256": sha256(original),
        "original_begin": dict(original_begin) if original_begin is not None else None,
        "original_pid": pid,
        "terminal": False,
        "prompt": False,
        "binding_revalidated": False,
        "binding_lost": False,
        "attempts": attempts,
        "send_count": 0,
        "errors": errors,
    }

    if original_begin is None or original_begin.get("cmd") != "run" or pid is None:
        event["method"] = "raw_ctrl_c_not_sent_missing_original_evidence"
        errors.append("missing original probe BEGIN or child PID")
        event["completed_utc"] = utc_now()
        return {
            "proved": False,
            "method": "UNPROVED_NO_ORIGINAL_BEGIN_OR_PID",
            "pid": pid,
            "child_exit_code": None,
            "channel_ready": False,
            "errors": errors,
            "cancel": event,
            "terminal_payload": None,
        }

    if expected_binding is None:
        event["method"] = "raw_ctrl_c_not_sent_missing_binding"
        event["binding_lost"] = True
        errors.append("missing final pre-dispatch bridge binding")
        event["completed_utc"] = utc_now()
        return {
            "proved": False,
            "method": "UNPROVED_NO_FINAL_BRIDGE_BINDING",
            "pid": pid,
            "child_exit_code": None,
            "channel_ready": False,
            "binding_lost": True,
            "errors": errors,
            "cancel": event,
            "terminal_payload": None,
        }

    try:
        # This check is host-only and must complete before any cancel byte is
        # written.  It binds the reconnect to the exact final PID/argv/script
        # and serial stat captured immediately before probe dispatch.
        revalidate_bridge_binding(expected_binding)
        event["binding_revalidated"] = True
    except BaseException as exc:
        event["binding_lost"] = True
        errors.append(f"cancel binding revalidation: {type(exc).__name__}: {exc}")

    deadline = time.monotonic() + timeout_value
    attempt_number = 0
    while not sent and not event["binding_lost"] and attempt_number < CANCEL_CONNECT_ATTEMPTS:
        attempt_number += 1
        attempt_started = utc_now()
        attempt: dict[str, object] = {
            "attempt": attempt_number,
            "started_utc": attempt_started,
            "completed_utc": None,
            "busy": False,
            "sent": False,
            "send_count": 0,
            "remainder_size": 0,
            "remainder_sha256": sha256(b""),
            "errors": [],
        }
        attempts.append(attempt)
        if attempt_number > 1:
            try:
                revalidate_bridge_binding(expected_binding)
                event["binding_revalidated"] = True
            except BaseException as exc:
                event["binding_lost"] = True
                error = f"cancel attempt binding revalidation: {type(exc).__name__}: {exc}"
                errors.append(error)
                attempt["errors"].append(error)
                attempt["completed_utc"] = utc_now()
                break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            attempt["errors"].append("cancel deadline expired before connection")
            attempt["completed_utc"] = utc_now()
            errors.append("cancel deadline expired before Ctrl-C")
            break
        try:
            connect_timeout = min(remaining, 3.0)
            with socket.create_connection(
                (session.host, session.port), timeout=connect_timeout
            ) as sock:
                # A busy bridge sends this greeting without accepting any
                # serial bytes.  Peek across the full source-backed selector
                # window before sending Ctrl-C so that a busy connection can
                # be closed/retried safely.
                greeting_state = _observe_cancel_connection(sock, deadline)
                if greeting_state == "busy":
                    attempt["busy"] = True
                    attempt["completed_utc"] = utc_now()
                    if attempt_number >= CANCEL_CONNECT_ATTEMPTS:
                        errors.append("bridge remained busy through bounded cancel attempts")
                    continue
                if greeting_state != "quiet":
                    error = (
                        "cancel connection was not quiet before raw Ctrl-C: "
                        f"{greeting_state}"
                    )
                    attempt["errors"].append(error)
                    errors.append(error)
                    attempt["completed_utc"] = utc_now()
                    break
                # The bridge can rebind during the quiet observation window;
                # revalidate immediately before the sole sendall below.
                try:
                    revalidate_bridge_binding(expected_binding)
                    event["binding_revalidated"] = True
                except BaseException as exc:
                    event["binding_lost"] = True
                    error = (
                        "cancel binding revalidation before send: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    attempt["errors"].append(error)
                    errors.append(error)
                    attempt["completed_utc"] = utc_now()
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportFailure("cancel deadline expired before Ctrl-C")
                # Mark the byte as sent before sendall so a partial write can
                # never trigger a reconnect or a second Ctrl-C.
                sent = True
                event["send_count"] = 1
                attempt["sent"] = True
                attempt["send_count"] = 1
                sent_utc = utc_now()
                sock.settimeout(min(0.2, max(0.001, remaining)))
                sock.sendall(cancel_byte)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportFailure("cancel deadline expired after Ctrl-C")
                remainder = _read_local_transcript(sock, remaining)
                attempt["remainder_size"] = len(remainder)
                attempt["remainder_sha256"] = sha256(remainder)
        except TransportFailure as exc:
            error = f"cancel transport: {exc}"
            attempt["errors"].append(error)
            errors.append(error)
            if exc.partial is not None and exc.partial.transcript is not None:
                remainder = exc.partial.transcript
                attempt["remainder_size"] = len(remainder)
                attempt["remainder_sha256"] = sha256(remainder)
        except Exception as exc:
            error = f"cancel transport: {type(exc).__name__}: {exc}"
            attempt["errors"].append(error)
            errors.append(error)
        finally:
            attempt["completed_utc"] = utc_now()
        # A sent byte ends this loop regardless of transport outcome.  A
        # pre-send connection error is boundedly retried only after the next
        # exact host-side bridge revalidation.
        if sent:
            break
    if not sent and not event["binding_lost"] and not errors:
        errors.append("raw Ctrl-C was not sent")
    event["sent"] = sent
    event["sent_utc"] = sent_utc
    event["completed_utc"] = utc_now()
    event["remainder_size"] = len(remainder)
    event["remainder_sha256"] = sha256(remainder)
    combined = original + remainder
    event["combined_size"] = len(combined)
    event["combined_sha256"] = sha256(combined)
    if remainder:
        session.transcript_parts.append(
            b"\n===== probe_cancel_remainder =====\n" + remainder
        )

    terminal_frame: Frame | None = None
    try:
        combined_begin_matches = list(BEGIN_RE.finditer(combined))
        if not combined_begin_matches:
            raise LiveError("cancel response lacks the original probe BEGIN")
        try:
            latest_begin = parse_fields(
                combined_begin_matches[-1].group("fields")
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise LiveError("cancel response has a malformed probe BEGIN") from exc
        if latest_begin != dict(original_begin):
            raise LiveError("cancel response latest BEGIN differs from original")
        terminal_frame = parse_last_frame(combined, "run")
        if terminal_frame.begin != dict(original_begin):
            raise LiveError("cancel terminal frame BEGIN differs from original")
        event["original_end"] = dict(terminal_frame.end)
        if terminal_frame.end.get("cmd") != "run":
            raise LiveError("cancel terminal frame command differs")
        if terminal_frame.end.get("seq") != original_begin.get("seq"):
            raise LiveError("cancel terminal frame sequence differs")
        event["terminal"] = True
    except (LiveError, ValueError) as exc:
        errors.append(f"cancel terminal frame: {exc}")

    prompt_proved = False
    if terminal_frame is not None:
        end_at = combined.rfind(b"A90P1 END ")
        prompt_proved = end_at >= 0 and (
            b"\na90:/#" in combined[end_at:]
            or b"\ra90:/#" in combined[end_at:]
        )
    event["prompt"] = prompt_proved
    termination_rc: int | None = None
    cancelled_text = b"cancelled by Ctrl-C" in combined
    terminating_text = f"run: terminating pid={pid}".encode("ascii") in combined
    child_terminated = False
    if terminal_frame is not None:
        try:
            termination_rc = int(terminal_frame.end.get("rc", ""), 0)
        except (TypeError, ValueError):
            termination_rc = None
        child_terminated = (
            termination_rc == -125
            and terminal_frame.end.get("status") == "error"
            and cancelled_text
            and terminating_text
            and b"[err] run rc=-125" in combined
        )
    event["termination_rc"] = termination_rc
    event["cancelled"] = cancelled_text
    event["child_terminated"] = child_terminated
    proved = bool(
        sent
        and terminal_frame is not None
        and event["terminal"] is True
        and prompt_proved
        and child_terminated
    )
    if not proved:
        errors.append("raw Ctrl-C did not prove the original terminal frame and child termination")
    return {
        "proved": proved,
        "method": "raw_ctrl_c_reconnect" if sent else "raw_ctrl_c_unproved",
        "pid": pid,
        "child_exit_code": None,
        "termination_rc": termination_rc,
        "channel_ready": bool(event["terminal"] and prompt_proved),
        "binding_lost": event["binding_lost"] is True,
        "errors": errors,
        "cancel": event,
        "terminal_payload": terminal_frame.payload if terminal_frame is not None else None,
    }


def parse_selftest(payload: bytes) -> dict[str, int]:
    matches = list(SELFTEST_RE.finditer(payload.replace(b"\r\n", b"\n")))
    if len(matches) != 1:
        raise LiveError("final selftest lacks one exact summary")
    values = {key: int(value) for key, value in matches[0].groupdict().items()}
    if (
        values["passed"] != EXPECTED_SELFTEST_PASS
        or values["warn"] != EXPECTED_SELFTEST_WARN
        or values["fail"] != 0
        or values["entries"] != EXPECTED_SELFTEST_ENTRIES
    ):
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


def _timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise LiveError(f"{label} is not an RFC3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise LiveError(f"{label} is not an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise LiveError(f"{label} is not UTC")
    return parsed


def _validate_lifecycle(lifecycle: Mapping[str, object]) -> None:
    required = {
        "acquisition_started_utc",
        "acquisition_completed_utc",
        "duration_monotonic_s",
        "receipt_publication_prewrite_utc",
    }
    missing = sorted(key for key in required if key not in lifecycle)
    if missing:
        raise LiveError(f"receipt lifecycle lacks {missing}")
    started = _timestamp(lifecycle["acquisition_started_utc"], "lifecycle start")
    completed = _timestamp(lifecycle["acquisition_completed_utc"], "lifecycle completion")
    prewrite = _timestamp(
        lifecycle["receipt_publication_prewrite_utc"],
        "lifecycle receipt prewrite",
    )
    if completed < started or prewrite < completed:
        raise LiveError("receipt lifecycle timestamps are out of order")
    duration = lifecycle["duration_monotonic_s"]
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(float(duration))
        or float(duration) < 0
    ):
        raise LiveError("receipt lifecycle duration is invalid")
    previous: dt.datetime | None = None
    ordered_keys = (
        "acquisition_started_utc",
        "bridge_validation_started_utc",
        "bridge_validation_completed_utc",
        "target_preflight_started_utc",
        "target_preflight_completed_utc",
        "ion_identity_started_utc",
        "ion_identity_completed_utc",
        "preclean_started_utc",
        "preclean_completed_utc",
        "upload_started_utc",
        "upload_completed_utc",
        "remote_hash_before_started_utc",
        "remote_hash_before_completed_utc",
        "ion_node_creation_started_utc",
        "ion_node_creation_completed_utc",
        "probe_dispatch_utc",
        "probe_child_exit_utc",
        "remote_hash_after_started_utc",
        "remote_hash_after_completed_utc",
        "cleanup_started_utc",
        "cleanup_completed_utc",
        "final_health_started_utc",
        "final_health_completed_utc",
        "acquisition_completed_utc",
        "receipt_publication_prewrite_utc",
    )
    for key in ordered_keys:
        value = lifecycle.get(key)
        if value is None:
            continue
        stamp = _timestamp(value, f"lifecycle {key}")
        if previous is not None and stamp < previous:
            raise LiveError("receipt lifecycle timestamps are not monotonic")
        previous = stamp
    absence_checks = lifecycle.get("absence_checks")
    if not isinstance(absence_checks, Mapping):
        raise LiveError("lifecycle absence checks are not an object")
    previous_absence: dt.datetime | None = None
    for evidence_id in ("absence_node", "absence_envelope", "absence_binary"):
        event = absence_checks.get(evidence_id)
        if not isinstance(event, Mapping):
            raise LiveError(f"lifecycle lacks {evidence_id} timestamps")
        begin = _timestamp(event.get("started_utc"), f"{evidence_id} start")
        end = _timestamp(event.get("completed_utc"), f"{evidence_id} completion")
        if end < begin or (previous_absence is not None and begin < previous_absence):
            raise LiveError("absence timestamps are out of order")
        previous_absence = end
        if event.get("ok") is not True:
            raise LiveError(f"{evidence_id} lifecycle event is not successful")


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
    previous_completed: dt.datetime | None = None
    for index, entry in enumerate(commands):
        if not isinstance(entry, Mapping):
            raise LiveError(f"command receipt entry {index} is not an object")
        evidence_id = entry.get("evidence_id")
        argv = entry.get("argv")
        if not isinstance(evidence_id, str) or evidence_id in seen:
            raise LiveError(f"command receipt entry {index} has duplicate/invalid id")
        seen.add(evidence_id)
        if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
            raise LiveError(f"command receipt entry {evidence_id} argv is invalid")
        command_started = _timestamp(entry.get("started_utc"), f"{evidence_id} start")
        command_completed = _timestamp(
            entry.get("completed_utc"), f"{evidence_id} completion"
        )
        if command_completed < command_started:
            raise LiveError(f"command receipt entry {evidence_id} timestamps are reversed")
        if previous_completed is not None and command_started < previous_completed:
            raise LiveError(f"command receipt entry {evidence_id} starts before prior command")
        previous_completed = command_completed
        duration = entry.get("duration_monotonic_s")
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(float(duration))
            or float(duration) < 0
        ):
            raise LiveError(f"command receipt entry {evidence_id} duration is invalid")
        child_exit = entry.get("child_exit_code")
        if argv[0] == "run":
            if child_exit is not None and (
                isinstance(child_exit, bool)
                or not isinstance(child_exit, int)
                or child_exit < 0
            ):
                raise LiveError(f"command receipt entry {evidence_id} child exit is invalid")
        elif child_exit != "NOT_APPLICABLE":
            raise LiveError(f"command receipt entry {evidence_id} child exit is not applicable")
        if "error" in entry:
            if "partial_over_limit" in entry and not isinstance(
                entry["partial_over_limit"], bool
            ):
                raise LiveError(
                    f"command receipt entry {evidence_id} partial bound marker is invalid"
                )
            for field_name in (
                "partial_payload_size", "partial_transcript_size", "partial_pid"
            ):
                field_value = entry.get(field_name)
                if field_value is not None and (
                    isinstance(field_value, bool)
                    or not isinstance(field_value, int)
                    or field_value < 0
                ):
                    raise LiveError(
                        f"command receipt entry {evidence_id} partial field is invalid"
                    )
            for field_name in ("partial_payload_sha256", "partial_transcript_sha256"):
                field_value = entry.get(field_name)
                if field_value is not None and (
                    not isinstance(field_value, str)
                    or re.fullmatch(r"[0-9a-f]{64}", field_value) is None
                ):
                    raise LiveError(
                        f"command receipt entry {evidence_id} partial hash is invalid"
                    )
            partial_begin = entry.get("partial_begin")
            partial_end = entry.get("partial_end")
            if partial_begin is not None or partial_end is not None:
                if not isinstance(partial_begin, Mapping) or not isinstance(partial_end, Mapping):
                    raise LiveError(
                        f"command receipt entry {evidence_id} partial frame is incomplete"
                    )
                if (
                    partial_begin.get("cmd") != argv[0]
                    or partial_end.get("cmd") != argv[0]
                    or partial_begin.get("seq") != partial_end.get("seq")
                ):
                    raise LiveError(
                        f"command receipt entry {evidence_id} partial frame differs"
                    )
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
        if (
            not isinstance(transcript_size, int)
            or isinstance(transcript_size, bool)
            or transcript_size <= 0
        ):
            raise LiveError(f"command receipt entry {evidence_id} transcript size is invalid")


def validate_fixed_command_surface(
    commands: Sequence[Mapping[str, object]],
    *,
    chunk_count: int,
    require_exact: bool = True,
) -> None:
    """Recheck every generated argv against the immutable 022R surface."""

    validate_command_log(
        commands, chunk_count=chunk_count, require_exact=require_exact
    )
    by_id = {
        entry["evidence_id"]: entry
        for entry in commands
        if isinstance(entry, Mapping) and isinstance(entry.get("evidence_id"), str)
    }

    def argv_for(evidence_id: str) -> list[str]:
        entry = by_id.get(evidence_id)
        if not isinstance(entry, Mapping) or not isinstance(entry.get("argv"), list):
            raise LiveError(f"command receipt lacks {evidence_id}")
        if "error" in entry and require_exact:
            raise LiveError(f"command receipt {evidence_id} retained an error")
        return entry["argv"]

    exact: dict[str, tuple[str, ...]] = {
        "version": ("version",),
        "cmdline": ("run", TOYBOX, "cat", "/proc/cmdline"),
        "ion_dev": ("run", TOYBOX, "cat", ION_DEV_PATH),
        "preclean": (
            "run", TOYBOX, "rm", "-f", REMOTE_ENVELOPE, REMOTE_BINARY, REMOTE_ION
        ),
        "envelope_footer": ("appendfile", REMOTE_ENVELOPE, "\n====\n"),
        "decode": (
            "run", TOYBOX, "uudecode", "-o", REMOTE_BINARY, REMOTE_ENVELOPE
        ),
        "chmod_binary": ("run", TOYBOX, "chmod", "700", REMOTE_BINARY),
        "remote_hash_before_run": (
            "run", TOYBOX, "sha256sum", REMOTE_BINARY
        ),
        "ion_node_create": (
            "run", TOYBOX, "mknod", REMOTE_ION, "c", "10", "94"
        ),
        "ion_node_chmod": ("run", TOYBOX, "chmod", "600", REMOTE_ION),
        "probe": PROBE_ARGV,
        "remote_hash_after_run": (
            "run", TOYBOX, "sha256sum", REMOTE_BINARY
        ),
        "cleanup_node": ("run", TOYBOX, "rm", "-f", REMOTE_ION),
        "cleanup_files": (
            "run", TOYBOX, "rm", "-f", REMOTE_ENVELOPE, REMOTE_BINARY
        ),
        "absence_node": ("run", TOYBOX, "test", "!", "-e", REMOTE_ION),
        "absence_envelope": (
            "run", TOYBOX, "test", "!", "-e", REMOTE_ENVELOPE
        ),
        "absence_binary": ("run", TOYBOX, "test", "!", "-e", REMOTE_BINARY),
        "final_version": ("version",),
        "final_cmdline": ("run", TOYBOX, "cat", "/proc/cmdline"),
        "final_selftest": ("selftest", "status"),
    }
    for evidence_id, expected in exact.items():
        if tuple(argv_for(evidence_id)) != expected:
            raise LiveError(f"command receipt {evidence_id} argv differs")
    header = argv_for("envelope_header")
    if tuple(header[:2]) != ("appendfile", REMOTE_ENVELOPE) or len(header) != 3:
        raise LiveError("envelope header argv differs")
    if header[2] != f"begin-base64 700 {EXPECTED_PROBE_BINARY_BASENAME}\n":
        raise LiveError("envelope header value differs")
    for index in range(chunk_count):
        payload = argv_for(f"payload_{index:04d}")
        if (
            len(payload) != 3
            or tuple(payload[:2]) != ("appendfile", REMOTE_ENVELOPE)
            or not isinstance(payload[2], str)
            or not payload[2]
            or len(payload[2]) > MAX_LEGACY_CHUNK
            or re.fullmatch(r"[A-Za-z0-9+/=]+", payload[2]) is None
        ):
            raise LiveError(f"payload_{index:04d} argv is not bounded base64")


def _validate_args(args: argparse.Namespace) -> None:
    if args.host != BRIDGE_HOST:
        raise LiveError("022R runner only accepts bridge host 127.0.0.1")
    if args.port != BRIDGE_PORT:
        raise LiveError("022R runner only accepts bridge port 54321")
    if not isinstance(args.timeout, (int, float)) or not 0 < args.timeout <= 300:
        raise LiveError("timeout must be within 0 < timeout <= 300 seconds")
    if not isinstance(args.probe_timeout, (int, float)) or not 0 < args.probe_timeout <= 1800:
        raise LiveError("probe timeout must be within 0 < timeout <= 1800 seconds")
    total_timeout = getattr(args, "total_timeout", DEFAULT_TOTAL_TIMEOUT)
    if not isinstance(total_timeout, (int, float)) or not 0 < total_timeout <= 3600:
        raise LiveError("total timeout must be within 0 < timeout <= 3600 seconds")
    reserve = cleanup_health_reserve(float(args.probe_timeout))
    prep_budget = float(total_timeout) - float(args.probe_timeout) - reserve
    if prep_budget < MIN_PRE_DISPATCH_BUDGET:
        raise LiveError(
            "total timeout leaves less than the minimum pre-dispatch budget"
        )
    if prep_budget <= 0:
        raise LiveError(
            "total timeout must exceed probe timeout plus cleanup/health reserve"
        )
    experiment_id = getattr(args, "experiment_id", None)
    if not isinstance(experiment_id, str) or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise LiveError("experiment ID has invalid characters")
    for name in ("binary", "source", "output_dir", "build_receipt"):
        if not isinstance(getattr(args, name), Path):
            setattr(args, name, Path(getattr(args, name)))
    expected_source = (REPO_ROOT / "tools" / EXPECTED_PROBE_SOURCE_BASENAME).resolve()
    if args.source.resolve() != expected_source:
        raise LiveError("022R source must be the exact checked-in probe source")
    if args.binary.name != EXPECTED_PROBE_BINARY_BASENAME:
        raise LiveError("022R binary basename must be v022r-pa28-probe")
    if args.build_receipt.name != "build-receipt.json":
        raise LiveError("022R build receipt basename must be build-receipt.json")


def run(args: argparse.Namespace) -> Path:
    """Perform one fixed 022R acquisition and return its private directory."""

    _validate_args(args)
    output_dir = ensure_private_output(args.output_dir)
    started = utc_now()
    acquisition_monotonic_started = time.monotonic()
    probe_timeout = float(args.probe_timeout)
    cleanup_health_reserve_seconds = cleanup_health_reserve(probe_timeout)
    total_timeout = float(getattr(args, "total_timeout", DEFAULT_TOTAL_TIMEOUT))
    total_deadline = time.monotonic() + total_timeout
    pre_dispatch_deadline = (
        total_deadline - probe_timeout - cleanup_health_reserve_seconds
    )
    lifecycle: dict[str, object] = {
        "acquisition_started_utc": started,
        "bridge_validation_started_utc": None,
        "bridge_validation_completed_utc": None,
        "target_preflight_started_utc": None,
        "target_preflight_completed_utc": None,
        "ion_identity_started_utc": None,
        "ion_identity_completed_utc": None,
        "preclean_started_utc": None,
        "preclean_completed_utc": None,
        "upload_started_utc": None,
        "upload_completed_utc": None,
        "remote_hash_before_started_utc": None,
        "remote_hash_before_completed_utc": None,
        "ion_node_creation_started_utc": None,
        "ion_node_creation_completed_utc": None,
        "probe_dispatch_utc": None,
        "probe_child_exit_utc": None,
        "remote_hash_after_started_utc": None,
        "remote_hash_after_completed_utc": None,
        "cleanup_started_utc": None,
        "cleanup_completed_utc": None,
        "absence_checks": {},
        "final_health_started_utc": None,
        "final_health_completed_utc": None,
        "receipt_publication_prewrite_utc": None,
        "acquisition_completed_utc": None,
        "duration_monotonic_s": None,
    }

    def mark(name: str) -> str:
        value = utc_now()
        lifecycle[name] = value
        return value

    session = _Session(
        BRIDGE_HOST,
        BRIDGE_PORT,
        float(args.timeout),
        deadline=pre_dispatch_deadline,
        total_deadline=total_deadline,
    )

    target: dict[str, object] | None = None
    target_bound = False
    bridge_binding: dict[str, object] | None = None
    pre_dispatch_revalidation: dict[str, object] | None = None
    version_frame: Frame | None = None
    cmdline_frame: Frame | None = None
    final_version_frame: Frame | None = None
    final_cmdline_frame: Frame | None = None
    final_selftest_frame: Frame | None = None
    ion_identity: str | None = None
    node_created = False
    probe_payload: bytes | None = None
    probe_jsonl: bytes | None = None
    probe_records: list[dict[str, object]] | None = None
    probe_cleanup: dict[str, object] | None = None
    dispatch_count = 0
    channel_ready = False
    probe_completion: dict[str, object] = {
        "proved": False,
        "method": "NOT_RUN",
        "pid": None,
        "child_exit_code": None,
        "channel_ready": False,
        "cancel": None,
        "errors": [],
    }
    upload: dict[str, object] | None = None
    remote_before: str | None = None
    remote_after: str | None = None
    build_receipt_bytes: bytes | None = None
    artifacts: dict[str, dict[str, object]] = {}
    build: dict[str, object] | None = None
    build_receipt_copy_meta: dict[str, object] | None = None
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
    binding_lost = False

    def fail(label: str, exc: BaseException) -> None:
        nonlocal primary_error
        if primary_error is None:
            primary_error = exc
        _record_error(failures, label, exc)

    try:
        # All local artifacts are read and pinned before bridge binding or the
        # first target command.  No build subprocess is ever launched here.
        binary = read_stable(args.binary, "probe binary")
        if not binary:
            raise LiveError("probe binary is empty")
        source = read_stable(args.source, "probe source")
        build_receipt_bytes = read_stable(args.build_receipt, "build receipt")
        runner = read_stable(RUNNER_SCRIPT_PATH, "runner script")
        bridge_script = read_stable(BRIDGE_SCRIPT_PATH, "bridge script")
        bridge_descriptor = _hash_descriptor(
            BRIDGE_SCRIPT_PATH, "bridge script", bridge_script
        )
        if (
            bridge_descriptor["basename"] != EXPECTED_BRIDGE_SCRIPT_BASENAME
            or bridge_descriptor["size_bytes"] != EXPECTED_BRIDGE_SCRIPT_SIZE
            or bridge_descriptor["sha256"] != EXPECTED_BRIDGE_SCRIPT_SHA256
        ):
            raise LiveError("actual serial_tcp_bridge.py bytes do not match the pinned bridge")
        artifacts = {
            "source": _hash_descriptor(args.source, "probe source", source),
            "binary": _hash_descriptor(args.binary, "probe binary", binary),
            "runner": _hash_descriptor(RUNNER_SCRIPT_PATH, "runner script", runner),
            "bridge_script": bridge_descriptor,
            "build_receipt": _hash_descriptor(
                args.build_receipt, "build receipt", build_receipt_bytes
            ),
        }
        build = validate_build_receipt(
            build_receipt_bytes,
            source=artifacts["source"],
            binary=artifacts["binary"],
        )

        mark("bridge_validation_started_utc")
        bridge_binding = validate_bridge_binding()
        mark("bridge_validation_completed_utc")
        mark("target_preflight_started_utc")
        version_frame = session.invoke("version", ("version",))
        cmdline_frame = session.invoke(
            "cmdline", ("run", TOYBOX, "cat", "/proc/cmdline")
        )
        require_child_exit_zero(cmdline_frame.payload, "cmdline")
        target = validate_target(version_frame.payload, cmdline_frame.payload)
        target_bound = True
        mark("target_preflight_completed_utc")

        mark("ion_identity_started_utc")
        ion_frame = session.invoke(
            "ion_dev", ("run", TOYBOX, "cat", ION_DEV_PATH)
        )
        ion_identity = parse_run_value(ion_frame.payload, "ion_dev")
        if ion_identity != EXPECTED_ION_DEV:
            raise LiveError(f"unexpected live ION misc identity: {ion_identity!r}")
        mark("ion_identity_completed_utc")

        mark("preclean_started_utc")
        preclean = session.invoke(
            "preclean",
            (
                "run", TOYBOX, "rm", "-f",
                REMOTE_ENVELOPE, REMOTE_BINARY, REMOTE_ION,
            ),
            allow_error=True,
        )
        require_frame_ok(preclean, "preclean")
        require_child_exit_zero(preclean.payload, "preclean")
        mark("preclean_completed_utc")
        mark("upload_started_utc")
        upload = upload_binary(session, binary, lifecycle=lifecycle)
        remote_before = str(upload["remote_before_run_sha256"])

        mark("ion_node_creation_started_utc")
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
        mark("ion_node_creation_completed_utc")

        # The listener/device/script identity is checked again after all
        # upload/node preparation and immediately before the one-shot probe.
        # A changed PID, argv, serial stat, or bridge bytes parks the run
        # without dispatch; post-binding cleanup still runs below.
        try:
            final_bridge_binding = revalidate_bridge_binding(bridge_binding)
        except BaseException:
            # The listener/device/script may have changed after target-bound
            # preparation.  No subsequent remote command is safe because the
            # final exact bridge authority has been lost.
            binding_lost = True
            raise
        pre_dispatch_revalidation = {
            "status": "PASS",
            "validated_utc": final_bridge_binding["validated_utc"],
            "bridge_binding": final_bridge_binding,
            "target": dict(target),
            "ion_identity": ion_identity,
            "command_argv": list(PROBE_ARGV),
        }

        # Reserve the post-dispatch window before issuing the one-shot probe.
        # The probe may consume only the pre-dispatch budget plus its own
        # bounded timeout; cleanup/health are never forced to share that
        # deadline after a transport timeout.
        if session.total_deadline is None:
            raise LiveError("022R session has no total deadline")
        session.deadline = session.total_deadline
        if time.monotonic() + probe_timeout > session.total_deadline - 0.001:
            raise LiveError("022R probe has no separately reserved cleanup/health window")

        mark("probe_dispatch_utc")
        probe_error: BaseException | None = None
        try:
            probe = session.invoke(
                "probe", PROBE_ARGV, probe_timeout, allow_error=True
            )
            dispatch_count = 1
            probe_payload = probe.payload
            try:
                require_frame_ok(probe, "probe A90P1 frame")
                require_child_exit_zero(probe_payload, "probe")
                probe_jsonl, probe_records = validate_probe_payload(probe_payload)
                probe_cleanup = next(
                    record for record in probe_records if record.get("type") == "cleanup"
                )
            except BaseException as exc:
                # A returned probe frame always gets a completion proof and a
                # remote-hash-after check; the probe itself is never reissued.
                probe_error = exc
        except BaseException as exc:
            # A timed-out transport may still expose a partial child banner or
            # frame through the transport exception.  Preserve it and use it
            # for the bounded termination proof below.
            if session.last_call_started:
                dispatch_count = 1
            probe_error = exc
            probe_payload = session.partial_payload("probe")

        final_binding_for_cancel = (
            pre_dispatch_revalidation.get("bridge_binding")
            if isinstance(pre_dispatch_revalidation, Mapping)
            else None
        )
        if dispatch_count == 0:
            # The session deadline can expire before the probe call writes any
            # bytes.  Preserve the prior prompt proof and do not send a raw
            # cancel for a command that was never dispatched.
            probe_completion = {
                "proved": False,
                "method": "NOT_DISPATCHED_DEADLINE",
                "pid": None,
                "child_exit_code": None,
                "channel_ready": session.prompt_ready,
                "cancel": None,
                "errors": ["probe command was not dispatched"],
            }
        else:
            cancel_budget = min(
                MAX_CANCEL_TIMEOUT,
                max(
                    BRIDGE_CLIENT_OBSERVATION_WINDOW + 0.25,
                    cleanup_health_reserve_seconds * 0.25,
                ),
            )
            probe_completion = prove_probe_completion(
                session,
                probe_payload,
                expected_binding=(
                    final_binding_for_cancel
                    if isinstance(final_binding_for_cancel, Mapping)
                    else None
                ),
                timeout=cancel_budget,
            )
        channel_ready = probe_completion.get("channel_ready") is True
        if probe_completion.get("binding_lost") is True:
            binding_lost = True
        terminal_payload = probe_completion.get("terminal_payload")
        # The terminal payload is retained in the dedicated private payload
        # sidecar below; never place raw bytes in the JSON receipt itself.
        probe_completion.pop("terminal_payload", None)
        if isinstance(terminal_payload, bytes) and probe_error is not None:
            # A timeout's raw cancel response is the terminal payload of the
            # original probe.  Retain it verbatim for the private incident
            # sidecar; it is not a successful probe JSONL result.
            probe_payload = terminal_payload
        if probe_completion.get("proved") is True:
            mark("probe_child_exit_utc")
        if probe_error is not None and not probe_completion["proved"]:
            raise LiveError(
                f"probe failed without bounded termination proof: {probe_completion}"
            ) from probe_error

        if not channel_ready:
            raise LiveError(
                "probe channel did not return to the original A90P1 prompt; "
                "remote commands are unsafe"
            )

        # A cancellation reconnect is itself a second host-side race point.
        # Recheck the exact final bridge binding before the first framed
        # post-probe command; drift here also parks the run with no cleanup
        # sent to an unknown listener.
        if isinstance(probe_completion.get("cancel"), Mapping):
            if not isinstance(final_binding_for_cancel, Mapping):
                binding_lost = True
                raise LiveError("cancel completion lacks final bridge binding")
            try:
                revalidate_bridge_binding(final_binding_for_cancel)
                probe_completion["cancel"][
                    "post_terminal_binding_revalidated"
                ] = True
            except BaseException as exc:
                binding_lost = True
                raise LiveError(
                    "bridge binding drifted after raw Ctrl-C before hash-after"
                ) from exc

        mark("remote_hash_after_started_utc")
        after = session.invoke(
            "remote_hash_after_run",
            ("run", TOYBOX, "sha256sum", REMOTE_BINARY),
            allow_error=True,
        )
        require_frame_ok(after, "remote binary hash after run")
        remote_after = _parse_remote_hash(
            after.payload, "remote binary hash after run"
        )
        mark("remote_hash_after_completed_utc")
        if remote_after != str(upload["binary_sha256"]):
            raise LiveError(
                f"remote binary changed during probe: {remote_after} != "
                f"{upload['binary_sha256']}"
            )
        if probe_error is not None:
            raise probe_error
    except BaseException as exc:
        fail("acquisition", exc)

    # A pre-probe failure after a complete framed command still leaves the
    # shell at its prompt.  Preserve that evidence when a local deadline check
    # sent no command, but first revalidate the exact bridge host-side before
    # any cleanup.  This second binding check is intentionally not an A90P1
    # command and cannot mutate the target.
    if target_bound and dispatch_count == 0 and not binding_lost:
        channel_ready = channel_ready or session.prompt_ready
        try:
            cleanup_bridge_binding = revalidate_bridge_binding(bridge_binding)
            pre_dispatch_revalidation = {
                "status": "PASS",
                "validated_utc": cleanup_bridge_binding["validated_utc"],
                "bridge_binding": cleanup_bridge_binding,
                "target": dict(target),
                "ion_identity": ion_identity,
                "command_argv": list(PROBE_ARGV),
            }
            session.deadline = session.total_deadline
        except BaseException as exc:
            binding_lost = True
            fail("pre_cleanup_bridge_revalidation", exc)

    # Once the exact target identity has been accepted, every post-binding
    # path performs all cleanup, absence, and final-health commands.  These
    # blocks deliberately continue after individual command failures.
    if target_bound and channel_ready and not binding_lost:
        cleanup["attempted"] = True
        mark("cleanup_started_utc")
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
            absence_started = utc_now()
            absence_events: dict[str, object] = lifecycle["absence_checks"]
            absence_events[evidence_id] = {
                "started_utc": absence_started,
                "completed_utc": None,
            }
            try:
                _remote_test_absence(session, evidence_id, path)
                absence_events[evidence_id]["completed_utc"] = utc_now()
                absence_events[evidence_id]["ok"] = True
            except BaseException as exc:
                absence_ok = False
                absence_events[evidence_id]["completed_utc"] = utc_now()
                absence_events[evidence_id]["ok"] = False
                _record_error(cleanup["errors"], evidence_id, exc)
                fail(evidence_id, exc)
        cleanup["absence_proved"] = absence_ok
        mark("cleanup_completed_utc")

        final_health["attempted"] = True
        mark("final_health_started_utc")
        health_errors: list[str] = final_health["errors"]
        try:
            final_version_frame = session.invoke("final_version", ("version",))
        except BaseException as exc:
            error = f"final_version: {type(exc).__name__}: {exc}"
            health_errors.append(error)
            fail("final_version", exc)
        try:
            final_cmdline_frame = session.invoke(
                "final_cmdline", ("run", TOYBOX, "cat", "/proc/cmdline")
            )
            require_child_exit_zero(final_cmdline_frame.payload, "final cmdline")
        except BaseException as exc:
            error = f"final_cmdline: {type(exc).__name__}: {exc}"
            health_errors.append(error)
            fail("final_cmdline", exc)
        final_target: dict[str, object] | None = None
        if final_version_frame is not None and final_cmdline_frame is not None:
            try:
                final_target = validate_target(
                    final_version_frame.payload, final_cmdline_frame.payload
                )
            except BaseException as exc:
                error = f"final_identity: {type(exc).__name__}: {exc}"
                health_errors.append(error)
                fail("final_identity", exc)
        else:
            health_errors.append("final_identity: prerequisite frame missing")
        try:
            final_selftest_frame = session.invoke(
                "final_selftest", ("selftest", "status")
            )
            require_frame_ok(final_selftest_frame, "final selftest")
            final_selftest = parse_selftest(final_selftest_frame.payload)
        except BaseException as exc:
            final_selftest = None
            error = f"final_selftest: {type(exc).__name__}: {exc}"
            health_errors.append(error)
            fail("final_selftest", exc)
        if not health_errors and final_target is not None and final_selftest is not None:
            final_health.update(
                {"ok": True, "target": final_target, "selftest": final_selftest}
            )
        else:
            if final_target is not None:
                final_health["target"] = final_target
            if final_selftest is not None:
                final_health["selftest"] = final_selftest
        mark("final_health_completed_utc")
    elif target_bound:
        # A timed-out active run may leave the shell inside the original
        # command.  Never send framed cleanup/health commands until the raw
        # cancellation path has proved the original END and prompt.
        reason = (
            "exact bridge binding was lost before dispatch"
            if binding_lost
            else "original A90P1 channel did not return to prompt"
        )
        cleanup["errors"].append(f"cleanup skipped: {reason}")
        final_health["errors"].append(f"final health skipped: {reason}")

    # Sidecars are private and no-clobber.  A malformed probe still retains
    # its exact framed payload; JSONL is retained only after strict validation.
    if probe_payload is not None:
        try:
            write_new(output_dir / RAW_PAYLOAD_BASENAME, probe_payload, 0o600)
            if probe_jsonl is not None:
                write_new(output_dir / RAW_BASENAME, probe_jsonl, 0o600)
        except BaseException as exc:
            fail("raw_publication", exc)
    if build_receipt_bytes is not None:
        try:
            write_new(
                output_dir / BUILD_RECEIPT_COPY_BASENAME,
                build_receipt_bytes,
                0o600,
            )
        except BaseException as exc:
            fail("build_receipt_publication", exc)
    try:
        write_new(
            output_dir / TRANSCRIPT_BASENAME,
            b"".join(session.transcript_parts),
            0o600,
        )
    except BaseException as exc:
        fail("transcript_publication", exc)

    completed = utc_now()
    lifecycle["acquisition_completed_utc"] = completed
    lifecycle["duration_monotonic_s"] = max(
        0.0, time.monotonic() - acquisition_monotonic_started
    )
    raw_meta: dict[str, object] | None = None
    raw_payload_meta: dict[str, object] | None = None
    transcript_meta: dict[str, object] | None = None
    for name, key in (
        (RAW_BASENAME, "raw"),
        (RAW_PAYLOAD_BASENAME, "raw_payload"),
        (TRANSCRIPT_BASENAME, "transcript"),
        (BUILD_RECEIPT_COPY_BASENAME, "build_receipt_copy"),
    ):
        path = output_dir / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
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
            elif key == "build_receipt_copy":
                build_receipt_copy_meta = metadata
            else:
                transcript_meta = metadata
        except BaseException as exc:
            fail(f"{key}_hash", exc)

    if upload is not None:
        try:
            validate_fixed_command_surface(
                session.commands,
                chunk_count=int(upload["chunk_count"]),
                require_exact=primary_error is None,
            )
        except BaseException as exc:
            fail("command_receipt", exc)

    success = (
        primary_error is None
        and target_bound
        and dispatch_count == 1
        and probe_records is not None
        and probe_cleanup is not None
        and raw_meta is not None
        and raw_payload_meta is not None
        and transcript_meta is not None
        and build_receipt_copy_meta is not None
        and upload is not None
        and remote_before is not None
        and remote_after == remote_before == str(upload["binary_sha256"])
        and bool(probe_completion["proved"])
        and bool(cleanup["node_removed"])
        and bool(cleanup["files_removed"])
        and bool(cleanup["absence_proved"])
        and bool(final_health["ok"])
        and not failures
    )
    # This is intentionally a pre-write boundary: the receipt cannot claim a
    # completion timestamp for a file that has not yet been published.
    lifecycle["receipt_publication_prewrite_utc"] = utc_now()
    receipt: dict[str, object] = {
        "schema": SCHEMA,
        "status": "PASS" if success else "INCIDENT",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_bound": target_bound,
        "dispatch_count": dispatch_count,
        "target": target,
        "target_frames": {
            "version": _frame_descriptor(version_frame),
            "cmdline": _frame_descriptor(cmdline_frame),
        },
        "bridge": {"host": BRIDGE_HOST, "port": BRIDGE_PORT},
        "bridge_binding": bridge_binding,
        "pre_dispatch_revalidation": pre_dispatch_revalidation,
        "command_argv": list(PROBE_ARGV),
        "probe_argv": list(PROBE_CLI_ARGS),
        "probe": {
            "schema": PROBE_SCHEMA,
            "records": len(probe_records) if probe_records is not None else 0,
            "child_pid": probe_completion.get("pid"),
            "child_exit_proved": probe_completion.get("proved") is True,
            "cleanup": probe_cleanup,
            "raw": raw_meta,
            "payload": raw_payload_meta,
        },
        "probe_completion": probe_completion,
        "lifecycle": lifecycle,
        "artifacts": artifacts,
        "source": artifacts.get("source"),
        "binary": artifacts.get("binary"),
        "runner": artifacts.get("runner"),
        "bridge_script": artifacts.get("bridge_script"),
        "build_receipt": artifacts.get("build_receipt"),
        "build_receipt_copy": build_receipt_copy_meta,
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
        "final_health": {
            **final_health,
            "frames": {
                "version": _frame_descriptor(final_version_frame),
                "cmdline": _frame_descriptor(final_cmdline_frame),
                "selftest": _frame_descriptor(final_selftest_frame),
            },
        },
        "transcript": transcript_meta,
        "commands": session.commands,
        "command_sequence_validated": bool(upload is not None and primary_error is None),
        "failures": failures,
        "scope": {
            "normal_ram_only": True,
            "ion_heap": EXPECTED_HEAP,
            "write_combine_mapping": True,
            "mmio": False,
            "smc": False,
            "protected_memory": False,
            "partition_write": False,
            "automatic_retries": False,
        },
        "claims": {
            "interpretation": "DEFERRED_TO_HOST_ANALYZER",
            "device_result": "RAW_ONLY" if success else "NOT_CLAIMED",
            "physical_alias": "NOT_ESTABLISHED",
        },
    }
    try:
        write_new(output_dir / RECEIPT_BASENAME, json_bytes(receipt), 0o600)
    except BaseException as exc:
        fail("receipt_publication", exc)
        raise LiveError(f"022R acquisition failed: {failures}") from exc
    if not success:
        raise LiveError(f"022R acquisition incident: {failures}")
    return output_dir


def collect(args: argparse.Namespace) -> Path:
    return run(args)


def _require_public_descriptor(
    value: object,
    label: str,
    *,
    basename: str | None = None,
) -> dict[str, object]:
    descriptor = _artifact_descriptor(value, label)
    if basename is not None and descriptor["basename"] != basename:
        raise LiveError(f"{label} basename differs")
    return descriptor


def _validate_bridge_snapshot(value: object, label: str) -> dict[str, object]:
    """Validate one private bridge identity snapshot before public promotion."""

    required = {
        "listener", "serial_device", "serial_identity", "serial_realpath",
        "serial_stat", "validated_utc", "process_pid", "process_argv",
        "bridge_process_script", "bridge_process_script_path",
        "bridge_process_script_descriptor", "unique_process",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise LiveError(f"{label} fields are incomplete")
    if (
        value.get("listener") != {"host": BRIDGE_HOST, "port": BRIDGE_PORT}
        or value.get("serial_device") != BRIDGE_SERIAL_DEVICE
        or value.get("serial_identity") != BRIDGE_SERIAL_ID
        or value.get("serial_realpath") != BRIDGE_SERIAL_DEVICE
        or value.get("bridge_process_script") != BRIDGE_PROCESS_SCRIPT
        or value.get("bridge_process_script_path") != str(BRIDGE_SCRIPT_PATH)
        or value.get("unique_process") is not True
    ):
        raise LiveError(f"{label} listener/device binding differs")
    serial_stat = value.get("serial_stat")
    if not isinstance(serial_stat, Mapping) or set(serial_stat) != {
        "st_dev", "st_ino", "st_rdev", "mode", "character_device"
    } or serial_stat.get("character_device") is not True:
        raise LiveError(f"{label} serial stat is incomplete")
    for key in ("st_dev", "st_ino", "st_rdev", "mode"):
        item = serial_stat.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise LiveError(f"{label} serial stat {key} is invalid")
    pid = value.get("process_pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise LiveError(f"{label} process PID is invalid")
    argv = value.get("process_argv")
    if not isinstance(argv, list) or not argv or any(
        not isinstance(item, str) or not item for item in argv
    ):
        raise LiveError(f"{label} process argv is invalid")
    script_path = BRIDGE_SCRIPT_PATH.resolve(strict=False)
    if sum(
        Path(item).resolve(strict=False) == script_path
        for item in argv
    ) != 1:
        raise LiveError(f"{label} process argv does not bind the pinned script")
    if _option_values(argv, "--host") != [BRIDGE_HOST]:
        raise LiveError(f"{label} process host option differs")
    if _option_values(argv, "--port") != [str(BRIDGE_PORT)]:
        raise LiveError(f"{label} process port option differs")
    if _option_values(argv, "--device") != [BRIDGE_SERIAL_DEVICE]:
        raise LiveError(f"{label} process device option differs")
    if _option_values(argv, "--expect-realpath") != [BRIDGE_SERIAL_DEVICE]:
        raise LiveError(f"{label} process realpath option differs")
    glob_values = _option_values(argv, "--device-glob")
    if len(glob_values) != 1 or BRIDGE_SERIAL_GLOB_TOKEN not in glob_values[0]:
        raise LiveError(f"{label} process device glob differs")
    descriptor = _artifact_descriptor(
        value.get("bridge_process_script_descriptor"),
        f"{label} script",
    )
    if descriptor != {
        "basename": EXPECTED_BRIDGE_SCRIPT_BASENAME,
        "size_bytes": EXPECTED_BRIDGE_SCRIPT_SIZE,
        "sha256": EXPECTED_BRIDGE_SCRIPT_SHA256,
    }:
        raise LiveError(f"{label} script bytes differ")
    _timestamp(value.get("validated_utc"), f"{label} validation")
    return dict(value)


def _validate_receipt_for_public(receipt: Mapping[str, object]) -> None:
    """Require every PASS gate before allowing public-manifest generation."""

    if receipt.get("schema") != SCHEMA or receipt.get("status") != "PASS":
        raise LiveError("only a complete PASS receipt may be publicly published")
    if receipt.get("target_bound") is not True or receipt.get("dispatch_count") != 1:
        raise LiveError("receipt target/dispatch gate is incomplete")
    if receipt.get("command_sequence_validated") is not True:
        raise LiveError("receipt command sequence was not validated")
    failures = receipt.get("failures")
    if not isinstance(failures, list) or failures:
        raise LiveError("receipt contains failures")
    target = receipt.get("target")
    expected_target = {
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
    if not isinstance(target, Mapping) or dict(target) != expected_target:
        raise LiveError("receipt target identity is incomplete")

    initial_binding = _validate_bridge_snapshot(
        receipt.get("bridge_binding"), "initial bridge binding"
    )
    pre_dispatch = receipt.get("pre_dispatch_revalidation")
    if not isinstance(pre_dispatch, Mapping) or set(pre_dispatch) != {
        "status", "validated_utc", "bridge_binding", "target", "ion_identity",
        "command_argv",
    }:
        raise LiveError("receipt pre-dispatch revalidation is incomplete")
    if pre_dispatch.get("status") != "PASS":
        raise LiveError("receipt pre-dispatch revalidation is not PASS")
    final_binding = _validate_bridge_snapshot(
        pre_dispatch.get("bridge_binding"), "pre-dispatch bridge binding"
    )
    identity_keys = set(initial_binding) | set(final_binding)
    identity_keys.discard("validated_utc")
    if any(initial_binding.get(key) != final_binding.get(key) for key in identity_keys):
        raise LiveError("receipt bridge binding changed before probe dispatch")
    initial_time = _timestamp(
        initial_binding.get("validated_utc"), "initial bridge validation"
    )
    final_time = _timestamp(
        final_binding.get("validated_utc"), "pre-dispatch bridge validation"
    )
    if final_time < initial_time or _timestamp(
        pre_dispatch.get("validated_utc"), "pre-dispatch validation"
    ) != final_time:
        raise LiveError("receipt pre-dispatch validation timestamps differ")
    if (
        pre_dispatch.get("target") != expected_target
        or pre_dispatch.get("ion_identity") != EXPECTED_ION_DEV
        or pre_dispatch.get("command_argv") != list(PROBE_ARGV)
    ):
        raise LiveError("receipt pre-dispatch target/ION/argv differs")

    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise LiveError("receipt artifacts are missing")
    expected_artifact_names = {
        "source", "binary", "runner", "bridge_script", "build_receipt"
    }
    if set(artifacts) != expected_artifact_names:
        raise LiveError("receipt artifact set differs")
    source = _require_public_descriptor(
        artifacts.get("source"), "source artifact", basename=EXPECTED_PROBE_SOURCE_BASENAME
    )
    binary = _require_public_descriptor(
        artifacts.get("binary"), "binary artifact", basename=EXPECTED_PROBE_BINARY_BASENAME
    )
    _require_public_descriptor(artifacts.get("runner"), "runner artifact")
    bridge_descriptor = _require_public_descriptor(
        artifacts.get("bridge_script"),
        "bridge artifact",
        basename=EXPECTED_BRIDGE_SCRIPT_BASENAME,
    )
    if (
        bridge_descriptor["size_bytes"] != EXPECTED_BRIDGE_SCRIPT_SIZE
        or bridge_descriptor["sha256"] != EXPECTED_BRIDGE_SCRIPT_SHA256
    ):
        raise LiveError("receipt bridge artifact is not canonical")
    build_receipt = _require_public_descriptor(
        artifacts.get("build_receipt"), "build receipt artifact", basename="build-receipt.json"
    )
    if (
        source["size_bytes"] != EXPECTED_PROBE_SOURCE_SIZE
        or source["sha256"] != EXPECTED_PROBE_SOURCE_SHA256
        or binary["size_bytes"] != EXPECTED_PROBE_BINARY_SIZE
        or binary["sha256"] != EXPECTED_PROBE_BINARY_SHA256
        or build_receipt["size_bytes"] <= 0
    ):
        raise LiveError("receipt source/binary pins are not canonical")
    for duplicate_name in ("source", "binary", "runner", "bridge_script", "build_receipt"):
        duplicate = receipt.get(duplicate_name)
        if duplicate != artifacts.get(duplicate_name):
            raise LiveError(f"receipt top-level {duplicate_name} descriptor differs")
    build_copy = _require_public_descriptor(
        receipt.get("build_receipt_copy"),
        "private build receipt copy",
        basename=BUILD_RECEIPT_COPY_BASENAME,
    )
    if build_copy != build_receipt:
        raise LiveError("private build receipt copy differs from input receipt")
    build = receipt.get("build")
    if not isinstance(build, Mapping) or set(build) != {
        "schema", "compiler_triple", "compiler_version", "compiler_command",
        "static", "reproducible_byte_identical",
    }:
        raise LiveError("receipt build summary is incomplete")
    if (
        build.get("schema") != BUILD_SCHEMA
        or build.get("compiler_triple") != EXPECTED_COMPILER_TRIPLE
        or build.get("compiler_version") != EXPECTED_COMPILER_VERSION
        or build.get("static") is not True
        or build.get("reproducible_byte_identical") is not True
        or not _valid_compiler_command(build.get("compiler_command"))
    ):
        raise LiveError("receipt build summary is not pinned")
    probe = receipt.get("probe")
    if not isinstance(probe, Mapping) or probe.get("schema") != PROBE_SCHEMA:
        raise LiveError("receipt probe summary is incomplete")
    if not isinstance(probe.get("records"), int) or probe.get("records", 0) <= 0:
        raise LiveError("receipt probe record count is invalid")
    if probe.get("child_exit_proved") is not True:
        raise LiveError("receipt probe exit is not proved")
    _require_public_descriptor(probe.get("raw"), "probe JSONL", basename=RAW_BASENAME)
    _require_public_descriptor(
        probe.get("payload"), "probe payload", basename=RAW_PAYLOAD_BASENAME
    )
    probe_cleanup = probe.get("cleanup")
    if not isinstance(probe_cleanup, Mapping) or set(probe_cleanup) != {
        "schema", "type", "attempted", "released", "ion_fd_closed",
        "allocation_fd_closed", "map_unmapped", "eviction_unmapped",
        "heaps_freed", "sample_buffers_freed", "status",
    }:
        raise LiveError("receipt probe cleanup record is incomplete")
    if (
        probe_cleanup.get("schema") != PROBE_SCHEMA
        or probe_cleanup.get("type") != "cleanup"
        or probe_cleanup.get("attempted") is not True
        or probe_cleanup.get("released") is not True
        or any(probe_cleanup.get(key) is not True for key in (
            "ion_fd_closed", "allocation_fd_closed", "map_unmapped",
            "eviction_unmapped", "heaps_freed", "sample_buffers_freed",
        ))
        or probe_cleanup.get("status") != "PASS"
    ):
        raise LiveError("receipt probe cleanup gate failed")
    completion = receipt.get("probe_completion")
    if not isinstance(completion, Mapping) or (
        completion.get("proved") is not True
        or completion.get("child_exit_code") != 0
        or not isinstance(completion.get("pid"), int)
        or completion.get("pid", 0) <= 0
    ):
        raise LiveError("receipt child completion gate failed")
    upload = receipt.get("upload")
    if not isinstance(upload, Mapping):
        raise LiveError("receipt upload summary is missing")
    if (
        upload.get("remote_path") != REMOTE_BINARY
        or upload.get("binary_size") != binary["size_bytes"]
        or upload.get("binary_sha256") != binary["sha256"]
        or upload.get("remote_sha256_verified") is not True
        or upload.get("remote_before_run_sha256") != binary["sha256"]
        or not isinstance(upload.get("chunk_count"), int)
        or upload.get("chunk_count", 0) < 1
    ):
        raise LiveError("receipt upload/hash-before gate failed")
    remote = receipt.get("remote_binary")
    if not isinstance(remote, Mapping) or (
        remote.get("before_run_sha256") != binary["sha256"]
        or remote.get("after_run_sha256") != binary["sha256"]
        or remote.get("unchanged") is not True
    ):
        raise LiveError("receipt remote hash-after gate failed")
    ion = receipt.get("ion_device")
    if not isinstance(ion, Mapping) or (
        ion.get("sysfs_identity") != EXPECTED_ION_DEV
        or ion.get("expected_identity") != EXPECTED_ION_DEV
        or ion.get("node_created") is not True
    ):
        raise LiveError("receipt ION identity gate failed")
    cleanup = receipt.get("cleanup")
    if not isinstance(cleanup, Mapping) or not all(
        cleanup.get(key) is True
        for key in ("attempted", "node_removed", "files_removed", "absence_proved")
    ):
        raise LiveError("receipt remote cleanup/absence gate failed")
    final_health = receipt.get("final_health")
    if not isinstance(final_health, Mapping) or (
        final_health.get("attempted") is not True
        or final_health.get("ok") is not True
    ):
        raise LiveError("receipt final health gate failed")
    selftest = final_health.get("selftest")
    if not isinstance(selftest, Mapping) or (
        selftest.get("passed") != EXPECTED_SELFTEST_PASS
        or selftest.get("warn") != EXPECTED_SELFTEST_WARN
        or selftest.get("fail") != 0
        or selftest.get("entries") != EXPECTED_SELFTEST_ENTRIES
    ):
        raise LiveError("receipt selftest gate failed")
    _require_public_descriptor(
        receipt.get("transcript"), "transport transcript", basename=TRANSCRIPT_BASENAME
    )
    lifecycle = receipt.get("lifecycle")
    if not isinstance(lifecycle, Mapping):
        raise LiveError("receipt lifecycle is missing")
    _validate_lifecycle(lifecycle)
    commands = receipt.get("commands")
    if not isinstance(commands, Sequence) or isinstance(commands, (str, bytes)):
        raise LiveError("receipt command log is missing")
    validate_fixed_command_surface(
        commands, chunk_count=int(upload["chunk_count"]), require_exact=True
    )


def _legacy_public_status(receipt: Mapping[str, object]) -> str:
    """Map a private acquisition result to the non-promotional public status."""

    try:
        _validate_receipt_for_public(receipt)
    except LiveError:
        return "NOT_PROMOTED"
    if receipt.get("status") == "PASS":
        return "DEVICE_ACQUISITION_VALIDATED"
    return "NOT_PROMOTED"


def _public_artifact(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    return _artifact_descriptor(value, "public artifact")


def _legacy_make_public_manifest(receipt: Mapping[str, object]) -> dict[str, object]:
    """Return a redacted manifest containing no private paths or raw bytes.

    The private receipt remains the source of exact command argv, bridge
    process argv, payloads, and transcripts.  This helper intentionally
    exposes only fixed-command identity, hashes, counts, and health gates.
    """

    if not isinstance(receipt, Mapping):
        raise LiveError("private receipt is not an object")
    _validate_receipt_for_public(receipt)
    status = receipt.get("status")
    artifacts_value = receipt.get("artifacts")
    artifacts: dict[str, object] = {}
    if isinstance(artifacts_value, Mapping):
        for name in ("source", "binary", "runner", "bridge_script", "build_receipt"):
            descriptor = _public_artifact(artifacts_value.get(name))
            if descriptor is not None:
                artifacts[name] = descriptor
    build_copy_descriptor = _public_artifact(receipt.get("build_receipt_copy"))
    if build_copy_descriptor is not None:
        artifacts["build_receipt_copy"] = build_copy_descriptor

    probe = receipt.get("probe")
    if not isinstance(probe, Mapping):
        probe = {}
    cleanup = receipt.get("cleanup")
    if not isinstance(cleanup, Mapping):
        cleanup = {}
    final_health = receipt.get("final_health")
    if not isinstance(final_health, Mapping):
        final_health = {}
    remote_binary = receipt.get("remote_binary")
    if not isinstance(remote_binary, Mapping):
        remote_binary = {}
    transcript = receipt.get("transcript")
    if not isinstance(transcript, Mapping):
        transcript = {}
    target_value = receipt.get("target")
    if isinstance(target_value, Mapping):
        target = {
            key: target_value[key]
            for key in (
                "model", "soc", "runtime_version", "runtime_build", "kernel",
                "bootloader", "debug_level", "force_upload", "dump_sink",
            )
            if key in target_value
        }
    else:
        target = None

    public_acquisition_status = public_status(receipt)
    public: dict[str, object] = {
        "schema": PUBLIC_SCHEMA,
        "status": public_acquisition_status,
        "acquisition_status": status,
        "experiment_id": receipt.get("experiment_id"),
        "started_utc": receipt.get("started_utc"),
        "completed_utc": receipt.get("completed_utc"),
        "target_bound": receipt.get("target_bound") is True,
        "target": target,
        "bridge": {"host": BRIDGE_HOST, "port": BRIDGE_PORT},
        "command": {
            "status": "REDACTED_FIXED_V022R",
            "argv_sha256": sha256(json_bytes(list(PROBE_ARGV))),
            "probe_schema": PROBE_SCHEMA,
        },
        "artifacts": artifacts,
        "probe": {
            "schema": PROBE_SCHEMA,
            "records": probe.get("records", 0),
            "child_exit_proved": probe.get("child_exit_proved") is True,
            "raw": _public_artifact(probe.get("raw")),
            "payload": _public_artifact(probe.get("payload")),
        },
        "remote_binary": {
            "before_run_sha256": remote_binary.get("before_run_sha256"),
            "after_run_sha256": remote_binary.get("after_run_sha256"),
            "unchanged": remote_binary.get("unchanged") is True,
        },
        "transcript": _public_artifact(transcript),
        "cleanup": {
            "attempted": cleanup.get("attempted") is True,
            "node_removed": cleanup.get("node_removed") is True,
            "files_removed": cleanup.get("files_removed") is True,
            "absence_proved": cleanup.get("absence_proved") is True,
        },
        "final_health": {
            "attempted": final_health.get("attempted") is True,
            "ok": final_health.get("ok") is True,
            "selftest_fail": (
                final_health.get("selftest", {}).get("fail")
                if isinstance(final_health.get("selftest"), Mapping)
                else None
            ),
        },
        "scope": {
            "normal_ram_only": True,
            "write_combine_mapping": True,
            "mmio": False,
            "smc": False,
            "protected_memory": False,
            "partition_write": False,
            "automatic_retries": False,
        },
        "claims": {
            "interpretation": "DEFERRED_TO_HOST_ANALYZER",
            "physical_alias": "NOT_ESTABLISHED",
            "device_result": "RAW_ONLY" if public_acquisition_status == "DEVICE_ACQUISITION_VALIDATED" else "NOT_CLAIMED",
        },
        "eligibility": "NOT_PROMOTED",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "definition_of_done": {
            "commands": {
                "status": "REDACTED_FIXED_V022R",
                "reason": "Exact argv and transcripts remain private; fixed command identity is hashed.",
            },
            "device_binding": {
                "status": "ATTESTED_IN_PRIVATE_RECEIPT" if receipt.get("target_bound") is True else "NOT_ATTESTED",
            },
            "cleanup": {
                "status": "PASS" if cleanup.get("absence_proved") is True else "NOT_PROVED",
            },
            "final_health": {
                "status": "PASS" if final_health.get("ok") is True else "NOT_PROVED",
            },
        },
    }
    return public


def _legacy_write_public_manifest(path: Path, receipt: Mapping[str, object]) -> Path:
    """Publish one fresh redacted manifest outside ``evidence/private``."""

    path = Path(path)
    lexical = path if path.is_absolute() else Path.cwd() / path
    _reject_symlink_components(lexical)
    resolved = lexical.resolve(strict=False)
    parts = resolved.parts
    for index in range(len(parts) - 1):
        if parts[index] == "evidence" and parts[index + 1] == "private":
            raise LiveError("public manifest cannot be written below evidence/private")
    if not resolved.parent.exists():
        resolved.parent.mkdir(parents=True, mode=0o755)
    write_new(resolved, json_bytes(make_public_manifest(receipt)), 0o644)
    return resolved


def _analysis_public_api():
    """Load the sole evidence-rooted public analyzer lazily."""

    # Keep this import local: the analyzer is the authority for loading every
    # private sidecar and does not import the runner.
    from tools import a90_pa28_live_analysis as analysis

    return analysis


def make_public_manifest(
    private_directory: Path,
    *,
    dependency_020m: Path | None = None,
    dependency_021: Path | None = None,
) -> dict[str, object]:
    """Delegate public promotion to the evidence-rooted analyzer.

    Receipt mappings are deliberately rejected.  The analyzer must reopen
    the private acquisition directory and verify receipt, JSONL, payload,
    transcript, build receipt, and dependencies together before publication.
    """

    if not isinstance(private_directory, Path):
        raise LiveError("public manifest requires a private acquisition Path")
    analysis = _analysis_public_api()
    try:
        return analysis.make_public_manifest(
            private_directory,
            dependency_020m=dependency_020m,
            dependency_021=dependency_021,
        )
    except analysis.AnalysisError as exc:
        raise LiveError(f"public analysis rejected acquisition: {exc}") from exc


def write_public_manifest(
    path: Path,
    private_directory: Path,
    *,
    dependency_020m: Path | None = None,
    dependency_021: Path | None = None,
) -> Path:
    """Delegate no-clobber public publication to the analyzer."""

    if not isinstance(path, Path) or not isinstance(private_directory, Path):
        raise LiveError("public publication requires Path arguments")
    analysis = _analysis_public_api()
    try:
        return analysis.write_public_manifest(
            path,
            private_directory,
            dependency_020m=dependency_020m,
            dependency_021=dependency_021,
        )
    except analysis.AnalysisError as exc:
        raise LiveError(f"public analysis rejected acquisition: {exc}") from exc


def public_status(
    private_directory: Path,
    *,
    dependency_020m: Path | None = None,
    dependency_021: Path | None = None,
) -> str:
    """Return a status only after analyzer-backed private-directory loading."""

    try:
        make_public_manifest(
            private_directory,
            dependency_020m=dependency_020m,
            dependency_021=dependency_021,
        )
    except LiveError:
        return "NOT_PROMOTED"
    return "DEVICE_ACQUISITION_VALIDATED"


redacted_public_manifest = make_public_manifest
redact_receipt = make_public_manifest
build_manifest = make_public_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument(
        "--source", type=Path, default=Path("tools/a90_pa28_probe_v022r.c")
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    # Kept as visible options so accidental non-loopback/noncanonical use is
    # diagnosed by _validate_args; they cannot select a different target.
    parser.add_argument("--host", default=BRIDGE_HOST)
    parser.add_argument("--port", type=int, default=BRIDGE_PORT)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--probe-timeout", type=float, default=900.0)
    parser.add_argument("--total-timeout", type=float, default=DEFAULT_TOTAL_TIMEOUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        output = run(args)
    except LiveError as exc:
        print(f"verification-022r: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
