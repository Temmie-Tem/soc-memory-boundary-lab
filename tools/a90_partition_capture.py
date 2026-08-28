#!/usr/bin/env python3
"""Capture an allowlisted set of A90 boot-firmware partitions read-only.

The target must already be pinned by an operator-controlled loopback ACM bridge.
The only block-device operations are ``sha256sum`` and ``cat``. Temporary block
device nodes are created in /dev and removed in a finally block; no partition is
opened for write and no arbitrary partition/path can be supplied on the CLI.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import socket
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from collections.abc import Callable
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, parse_fields, write_new
    from tools.a90_autohud_arbitration import run_stophud
    from tools.a90_pa28_live import revalidate_bridge_binding, validate_bridge_binding
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, parse_fields, write_new
    from a90_autohud_arbitration import run_stophud  # type: ignore
    from a90_pa28_live import revalidate_bridge_binding, validate_bridge_binding  # type: ignore


SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
BEGIN_LINE_RE = re.compile(rb"A90P1 BEGIN (?P<fields>[^\r\n]+)\r?\n")
END_AFTER_PAYLOAD_RE = re.compile(
    rb"^\r\n\[done\] cat \([0-9]+ms\)\r\n"
    rb"A90P1 END (?P<fields>[^\r\n]+)\r\n"
    rb"a90:/# ?(?:\r?\n)?$"
)
SHA256_LINE_RE = re.compile(rb"(?m)^([0-9a-f]{64})  (/dev/[A-Za-z0-9_.-]+)\r?$")

SECTOR_BYTES = 512
PARAM_DEVNAME = "sda10"
PARAM_PARTNAME = "param"
PARAM_MAJOR = 8
PARAM_MINOR = 10
PARAM_SECTORS = 20_480
PARAM_PARTITION_BYTES = 0xA00000
PARAM_START_SECTOR = 125_080
PARAM_READ_ONLY = 0
PARAM_LOGICAL_BLOCK_SIZE = 4096
MAX_PARTITION_BYTES = PARAM_PARTITION_BYTES
# The receive buffer is bounded to the requested payload plus a deliberately
# small fixed amount for the BEGIN/prompt/END framing.  A peer that sends an
# overrun is refused as soon as the excess arrives rather than being buffered
# until the outer timeout.
MAX_BINARY_PROTOCOL_OVERHEAD = 64 * 1024
MAX_BINARY_FRAME_BYTES = MAX_PARTITION_BYTES + MAX_BINARY_PROTOCOL_OVERHEAD
MAX_NODE_STAT_BYTES = 256
TOYBOX = "/bin/toybox"
DEVICE_NODE_PREFIX = "/dev/sdm855_mblab_"
MutationBinding = Callable[[str], object]
MAX_COMMAND_TIMEOUT = 120.0
MAX_CAPTURE_TIMEOUT = 600.0
REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 54321
PARTITION_CAPTURE_JOURNAL_SCHEMA = (
    "sdm855-memory-boundary-live-firmware-capture-arbitration-journal-v1"
)
PARTITION_CAPTURE_JOURNAL_NAME = "capture-journal.json"

# The standalone helper's endpoint and target identity are fixed.  Identity is
# still returned from the live version/cmdline exchange and copied into the
# receipts; these constants are only the accepted target contract.
TARGET_MODEL = "SM-A908N"
TARGET_SOC = "SM8150"
TARGET_BOOTLOADER = "A908NKSU5EWA3"
TARGET_RUNTIME = "v2321-usb-clean-identity-rodata"
TARGET_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"

# The native ``run`` command wraps the child output in these two lines.  The
# wrapper is deliberately parsed instead of treating an arbitrary payload as
# a successful mutation/absence check.  A90P1's outer exchange already checks
# the command's rc/status; this parser checks the inner toybox receipt.
TOYBOX_RUN_RE = re.compile(rb"run: pid=[0-9]+, q/Ctrl-C cancels")
TOYBOX_EXIT_RE = re.compile(rb"\[exit ([0-9]+)\]")

PARTITION_SIZE = {
    # Param is not part of the default firmware inventory, but is available
    # through the explicit param helper below and must retain its own exact
    # geometry contract.
    PARAM_PARTNAME: PARAM_PARTITION_BYTES,
    "xbl": 4 * 1024 * 1024,
    # Live GPT reports 8,104 512-byte sectors, not a full 4 MiB.
    "xbl_config": 4_149_248,
    "aop": 512 * 1024,
    "aopbak": 512 * 1024,
    "devcfg": 128 * 1024,
    "devcfgbak": 128 * 1024,
    "tz": 4 * 1024 * 1024,
    "tzbak": 4 * 1024 * 1024,
    "hyp": 1024 * 1024,
    "hypbak": 1024 * 1024,
    "abl": 4 * 1024 * 1024,
    "ablbak": 4 * 1024 * 1024,
}
ALLOWED_PARTNAMES = tuple(PARTITION_SIZE)
DISCOVERY_DEVNAMES = (
    "sdb1",
    "sdb2",
    "sdc1",
    "sdc2",
    *(f"sdd{index}" for index in range(1, 35)),
)
ALLOWED_NODE_DEVNAMES = frozenset((*DISCOVERY_DEVNAMES, "sda10"))
HISTORICAL_SHA256 = {
    "sdb1": "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37",
    "sdc1": "ae1191b5d70e6de9fd67c6d629bc93aa567296605d30b5c9196ff58fcc26cb50",
    "sdd7": "eadd6c78daca52221e1e3419f34a53eac7c1e2c2bb46c9b663325df1998b9c7c",
    "sdd22": "0399578253dd293dfc961c6a1077f660834df3ae5e1d65555f4225e327a03d14",
    "sdd8": "1db19d11a5ce6865e3fbcabadfbdaa9045e75f144b8bc8593a58338c20a3120c",
}


@dataclass(frozen=True)
class Partition:
    partname: str
    devname: str
    major: int
    minor: int
    sectors: int
    byte_size: int
    read_only: int
    logical_block_size: int

    @property
    def artifact_id(self) -> str:
        return f"{self.partname}--{self.devname}"

    @property
    def node_path(self) -> str:
        return DEVICE_NODE_PREFIX + self.devname


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_timeout(value: object, label: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
        or float(value) > maximum
    ):
        raise ValueError(f"{label} must be finite, positive, and <= {maximum:g}s")
    return float(value)


def text_exchange(
    host: str,
    port: int,
    evidence_id: str,
    argv: tuple[str, ...],
    timeout: float,
) -> bytes:
    try:
        return exchange(host, port, Command(evidence_id, argv), timeout).payload
    except Exception as exc:
        raise RuntimeError(
            f"read-only A90P1 exchange failed at {evidence_id}: {argv!r}: {exc}"
        ) from exc


def parse_uevent(payload: bytes) -> dict[str, str]:
    text = payload.decode("ascii", errors="strict")
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            continue
        if "=" not in line:
            raise ValueError(f"malformed uevent line: {line!r}")
        key, value = line.split("=", 1)
        if not key or key in result:
            raise ValueError(f"duplicate or empty uevent key: {key!r}")
        result[key] = value
    return result


def parse_decimal(payload: bytes, label: str) -> int:
    text = payload.decode("ascii", errors="strict").strip()
    if not text.isdecimal():
        raise ValueError(f"{label} is not a decimal integer: {text!r}")
    return int(text, 10)


def discover_partitions(host: str, port: int, timeout: float) -> list[Partition]:
    found: list[Partition] = []
    for devname in DISCOVERY_DEVNAMES:
        uevent = parse_uevent(
            text_exchange(
                host,
                port,
                f"uevent_{devname}",
                ("cat", f"/sys/class/block/{devname}/uevent"),
                timeout,
            )
        )
        partname = uevent.get("PARTNAME", "")
        if partname == PARAM_PARTNAME:
            raise ValueError(
                f"param identity appeared on non-fixed discovery device {devname}"
            )
        if partname not in PARTITION_SIZE:
            continue
        if uevent.get("DEVNAME") != devname or uevent.get("DEVTYPE") != "partition":
            raise ValueError(f"unexpected uevent identity for {devname}: {uevent}")
        major = int(uevent["MAJOR"], 10)
        minor = int(uevent["MINOR"], 10)
        sectors = parse_decimal(
            text_exchange(
                host,
                port,
                f"size_{devname}",
                ("cat", f"/sys/class/block/{devname}/size"),
                timeout,
            ),
            f"{devname} sectors",
        )
        read_only = parse_decimal(
            text_exchange(
                host,
                port,
                f"ro_{devname}",
                ("cat", f"/sys/class/block/{devname}/ro"),
                timeout,
            ),
            f"{devname} ro",
        )
        parent_devname = re.sub(r"[0-9]+$", "", devname)
        logical_block_size = parse_decimal(
            text_exchange(
                host,
                port,
                f"logical_block_size_{devname}",
                (
                    "cat",
                    f"/sys/class/block/{parent_devname}/queue/logical_block_size",
                ),
                timeout,
            ),
            f"{devname} logical block size",
        )
        byte_size = sectors * SECTOR_BYTES
        partition = Partition(
            partname,
            devname,
            major,
            minor,
            sectors,
            byte_size,
            read_only,
            logical_block_size,
        )
        validate_partition(partition)
        found.append(partition)
    return sorted(found, key=lambda item: (item.partname, item.devname))


def discover_param_partition(
    host: str, port: int, timeout: float
) -> tuple[Partition, int]:
    """Discover param only through its complete pinned geometry contract."""

    prefix = f"/sys/class/block/{PARAM_DEVNAME}"
    uevent = parse_uevent(
        text_exchange(host, port, "param_uevent", ("cat", f"{prefix}/uevent"), timeout)
    )
    expected_identity = {
        "DEVNAME": PARAM_DEVNAME,
        "DEVTYPE": "partition",
        "PARTNAME": PARAM_PARTNAME,
        "PARTN": "10",
        "MAJOR": str(PARAM_MAJOR),
        "MINOR": str(PARAM_MINOR),
    }
    if any(uevent.get(key) != value for key, value in expected_identity.items()):
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
        PARAM_PARTNAME,
        PARAM_DEVNAME,
        PARAM_MAJOR,
        PARAM_MINOR,
        sectors,
        sectors * SECTOR_BYTES,
        read_only,
        logical_block_size,
    )
    validate_param_partition(partition, start_sector)
    return partition, start_sector


def validate_partition(partition: Partition) -> None:
    if partition.partname == PARAM_PARTNAME:
        if any(
            type(getattr(partition, key)) is not type(expected)
            for key, expected in {
                "partname": PARAM_PARTNAME,
                "devname": PARAM_DEVNAME,
                "major": PARAM_MAJOR,
                "minor": PARAM_MINOR,
                "sectors": PARAM_SECTORS,
                "byte_size": PARAM_PARTITION_BYTES,
                "read_only": PARAM_READ_ONLY,
                "logical_block_size": PARAM_LOGICAL_BLOCK_SIZE,
            }.items()
        ):
            raise ValueError("param geometry contains a non-exact scalar type")
        if partition.devname != PARAM_DEVNAME:
            raise ValueError("param partition must be the fixed sda10 device")
        if (partition.major, partition.minor) != (PARAM_MAJOR, PARAM_MINOR):
            raise ValueError("param major/minor differs from the pinned geometry")
        if partition.sectors != PARAM_SECTORS or partition.byte_size != PARAM_PARTITION_BYTES:
            raise ValueError("param size differs from the pinned 10 MiB geometry")
        if partition.read_only != PARAM_READ_ONLY:
            raise ValueError("param read-only state differs from the pinned zero value")
        if partition.logical_block_size != PARAM_LOGICAL_BLOCK_SIZE:
            raise ValueError("param logical block size differs from the pinned 4096 value")
        return
    expected_size = PARTITION_SIZE[partition.partname]
    if partition.byte_size != expected_size:
        raise ValueError(
            f"{partition.artifact_id} size mismatch: {partition.byte_size} != {expected_size}"
        )
    if partition.byte_size <= 0 or partition.byte_size > MAX_PARTITION_BYTES:
        raise ValueError(f"{partition.artifact_id} exceeds bounded capture size")
    if partition.read_only != 1:
        raise ValueError(f"{partition.artifact_id} is not sysfs read-only")
    if partition.logical_block_size not in {512, 4096}:
        raise ValueError(
            f"{partition.artifact_id} has unexpected logical block size "
            f"{partition.logical_block_size}"
        )
    if partition.major < 1 or partition.minor < 0:
        raise ValueError(f"{partition.artifact_id} has invalid major/minor")


def select_partitions(
    partitions: Sequence[Partition], requested: Sequence[str]
) -> list[Partition]:
    if not requested:
        return list(partitions)
    requested_set = set(requested)
    unknown = requested_set - set(ALLOWED_PARTNAMES)
    if unknown:
        raise ValueError(f"unknown partition names requested: {sorted(unknown)}")
    selected = [item for item in partitions if item.partname in requested_set]
    found_names = {item.partname for item in selected}
    missing = requested_set - found_names
    if missing:
        raise ValueError(f"requested partition names not found live: {sorted(missing)}")
    return selected


def parse_binary_frame(transcript: bytes, expected_size: int) -> tuple[dict[str, str], bytes]:
    if (
        type(expected_size) is not int
        or expected_size <= 0
        or expected_size > MAX_PARTITION_BYTES
    ):
        raise ValueError(f"requested binary size is outside the fixed bound: {expected_size!r}")
    if type(transcript) is not bytes:
        raise ValueError("binary transcript must be bytes")
    if len(transcript) > expected_size + MAX_BINARY_PROTOCOL_OVERHEAD:
        raise ValueError("binary transcript overrun exceeds the fixed protocol overhead bound")
    begin_match = None
    begin_fields: dict[str, str] | None = None
    for match in BEGIN_LINE_RE.finditer(transcript):
        fields = parse_fields(match.group("fields"))
        if fields.get("cmd") == "cat":
            begin_match = match
            begin_fields = fields
            break
    if begin_match is None or begin_fields is None:
        raise ValueError("binary transcript lacks a cat BEGIN frame")
    payload_start = begin_match.end()
    payload_end = payload_start + expected_size
    if payload_end > len(transcript):
        raise ValueError("binary transcript is shorter than advertised partition size")
    payload = transcript[payload_start:payload_end]
    trailer = transcript[payload_end:]
    trailer_match = END_AFTER_PAYLOAD_RE.fullmatch(trailer)
    if trailer_match is None:
        raise ValueError("binary transcript trailer is not exact")
    end_fields = parse_fields(trailer_match.group("fields"))
    for key in ("seq", "cmd"):
        if begin_fields.get(key) != end_fields.get(key):
            raise ValueError(f"binary A90P1 {key} differs between BEGIN and END")
    if int(end_fields.get("rc", "1"), 0) != 0 or end_fields.get("status") != "ok":
        raise ValueError(f"binary cat failed: {end_fields}")
    return end_fields, payload


def binary_exchange(
    host: str,
    port: int,
    node_path: str,
    expected_size: int,
    timeout: float,
) -> tuple[dict[str, str], bytes]:
    if host != BRIDGE_HOST or port != BRIDGE_PORT:
        raise ValueError("binary capture only accepts the pinned 127.0.0.1:54321 bridge")
    if (
        type(expected_size) is not int
        or expected_size <= 0
        or expected_size > MAX_PARTITION_BYTES
    ):
        raise ValueError(f"requested binary size is outside the fixed bound: {expected_size!r}")
    if not isinstance(node_path, str) or not node_path.startswith("/dev/"):
        raise ValueError(f"binary node path is not an absolute device path: {node_path!r}")
    _validate_node_path(node_path)
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(float(timeout))
        or timeout <= 0
        or float(timeout) > MAX_CAPTURE_TIMEOUT
    ):
        raise ValueError("binary capture timeout must be positive")
    deadline = time.monotonic() + timeout
    data = bytearray()
    payload_end: int | None = None
    max_frame_bytes = expected_size + MAX_BINARY_PROTOCOL_OVERHEAD
    with socket.create_connection((host, port), timeout=min(timeout, 3.0)) as sock:
        sock.settimeout(0.25)
        sock.sendall(b"\ncmdv1 cat " + node_path.encode("ascii") + b"\n")
        while time.monotonic() < deadline:
            try:
                remaining = max_frame_bytes - len(data)
                if remaining <= 0:
                    raise ValueError(
                        f"binary transcript exceeds {max_frame_bytes} byte fixed bound"
                    )
                chunk = sock.recv(min(64 * 1024, remaining + 1))
            except socket.timeout:
                continue
            if not chunk:
                break
            if len(data) + len(chunk) > max_frame_bytes:
                raise ValueError(
                    f"binary transcript overrun: received more than {max_frame_bytes} bytes"
                )
            data.extend(chunk)
            if payload_end is None:
                for match in BEGIN_LINE_RE.finditer(data):
                    fields = parse_fields(match.group("fields"))
                    if fields.get("cmd") == "cat":
                        payload_end = match.end() + expected_size
                        break
            if payload_end is not None and len(data) > payload_end + MAX_BINARY_PROTOCOL_OVERHEAD:
                raise ValueError(
                    "binary transcript trailer exceeds the fixed protocol overhead bound"
                )
            if payload_end is not None and len(data) >= payload_end:
                tail = data[payload_end:]
                if b"A90P1 END " in tail and b"a90:/#" in tail:
                    return parse_binary_frame(bytes(data), expected_size)
    raise TimeoutError(
        f"timed out after {timeout}s capturing {expected_size} bytes from {node_path}"
    )


def run_toybox(
    host: str,
    port: int,
    evidence_id: str,
    args: tuple[str, ...],
    timeout: float,
) -> bytes:
    return text_exchange(host, port, evidence_id, ("run", TOYBOX, *args), timeout)


def parse_toybox_payload(payload: bytes, label: str = "toybox command") -> bytes:
    """Return child stdout after validating the complete native ``run`` frame.

    ``run_toybox`` intentionally retains the original payload for callers
    which need to parse command output (for example ``sha256sum``).  Cleanup
    and absence proofs use this stricter helper so a malformed or duplicated
    inner receipt can never be mistaken for a successful command.
    """

    normalized = payload.replace(b"\r\n", b"\n")
    lines = normalized.splitlines()
    nonempty_lines = [line for line in lines if line]
    run_lines = [line for line in nonempty_lines if TOYBOX_RUN_RE.fullmatch(line)]
    exit_matches = [match for match in TOYBOX_EXIT_RE.finditer(normalized)]
    if len(run_lines) != 1:
        raise ValueError(f"{label} lacks exactly one toybox run banner")
    if len(exit_matches) != 1 or int(exit_matches[0].group(1), 10) != 0:
        raise ValueError(f"{label} lacks exact toybox exit 0")
    exit_line = f"[exit {int(exit_matches[0].group(1), 10)}]".encode("ascii")
    if (
        not nonempty_lines
        or not TOYBOX_RUN_RE.fullmatch(nonempty_lines[0])
        or nonempty_lines[-1] != exit_line
        or sum(line == exit_line for line in nonempty_lines) != 1
    ):
        raise ValueError(f"{label} does not have terminal toybox framing")
    if sum(line == exit_line for line in lines) != 1:
        raise ValueError(f"{label} has a malformed or duplicate toybox exit")
    body: list[bytes] = []
    for line in lines:
        if TOYBOX_RUN_RE.fullmatch(line) or TOYBOX_EXIT_RE.fullmatch(line):
            continue
        body.append(line)
    return b"\n".join(body)


def _validate_node_path(path: str) -> None:
    if not isinstance(path, str) or not path.startswith(DEVICE_NODE_PREFIX):
        raise ValueError(f"temporary node path is outside the fixed namespace: {path!r}")
    devname = path[len(DEVICE_NODE_PREFIX) :]
    if devname not in ALLOWED_NODE_DEVNAMES:
        raise ValueError(f"temporary node path is not an allowlisted device: {path!r}")


def _parse_node_stat_identity(
    payload: bytes, partition: Partition
) -> dict[str, str]:
    """Parse the bounded native ``stat`` record for one temporary node.

    V2321 emits one metadata line followed by one ``rdev`` line.  Parse the
    complete record rather than searching for a substring: ``8:100``,
    ``18:10``, duplicate fields, and trailing garbage must never satisfy the
    expected ``8:10`` device identity.
    """

    if type(payload) is not bytes:
        raise ValueError("temporary node stat payload must be bytes")
    if len(payload) > MAX_NODE_STAT_BYTES:
        raise ValueError("temporary node stat exceeds the fixed size bound")
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("temporary node stat is not strict ASCII") from exc
    if "\x00" in text:
        raise ValueError("temporary node stat contains malformed line framing")
    # Normalize only CRLF pairs, then compare the complete two-line record.
    # The terminal LF is optional because the native stat command's exact live
    # receipt has none; one terminal LF remains accepted for retained fixtures.
    # Any bare CR, extra/empty line, duplicate/unknown field, spacing change,
    # or rdev prefix/suffix lookalike fails this closed grammar.
    normalized = payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise ValueError("temporary node stat contains malformed line framing")
    expected_metadata = b"mode=0600 uid=0 gid=0 size=0"
    expected_rdev = f"rdev={partition.major}:{partition.minor}".encode("ascii")
    allowed = {
        expected_metadata + b"\n" + expected_rdev,
        expected_metadata + b"\n" + expected_rdev + b"\n",
    }
    if normalized not in allowed:
        raise ValueError(f"temporary node stat record is not exact: {text!r}")
    return {
        "mode": "0600",
        "uid": "0",
        "gid": "0",
        "size": "0",
        "rdev": f"{partition.major}:{partition.minor}",
    }


def prove_node_absent(
    host: str,
    port: int,
    path: str,
    timeout: float,
    evidence_prefix: str = "node_absent",
    *,
    before_mutation: MutationBinding | None = None,
) -> None:
    """Require both pathname and symlink absence using strict toybox frames."""

    _validate_node_path(path)
    checks = (
        ("test", "!", "-e", path),
        ("test", "!", "-L", path),
    )
    for index, argv in enumerate(checks, 1):
        if before_mutation is not None:
            before_mutation(f"{evidence_prefix}_{index}")
        output = parse_toybox_payload(
            run_toybox(host, port, f"{evidence_prefix}_{index}", argv, timeout),
            f"{evidence_prefix}_{index}",
        )
        if output not in (b"", b"\n"):
            raise ValueError(
                f"{evidence_prefix}_{index} returned unexpected output: {output!r}"
            )


def remove_node(
    host: str,
    port: int,
    partition: Partition,
    timeout: float,
    *,
    before_mutation: MutationBinding | None = None,
) -> None:
    _validate_node_path(partition.node_path)
    if before_mutation is not None:
        before_mutation(f"cleanup_rm_{partition.devname}")
    rm_output = parse_toybox_payload(
        run_toybox(
            host,
            port,
            f"cleanup_{partition.devname}",
            ("rm", "-f", partition.node_path),
            timeout,
        ),
        f"cleanup_{partition.devname}",
    )
    if rm_output not in (b"", b"\n"):
        raise ValueError(
            f"cleanup_{partition.devname} returned unexpected output: {rm_output!r}"
        )
    prove_node_absent(
        host,
        port,
        partition.node_path,
        timeout,
        f"cleanup_absent_{partition.devname}",
        before_mutation=before_mutation,
    )


def create_and_validate_node(
    host: str,
    port: int,
    partition: Partition,
    timeout: float,
    *,
    before_mutation: MutationBinding | None = None,
) -> None:
    remove_node(host, port, partition, timeout, before_mutation=before_mutation)
    if before_mutation is not None:
        before_mutation(f"mknodb_{partition.devname}")
    text_exchange(
        host,
        port,
        f"mknodb_{partition.devname}",
        (
            "mknodb",
            partition.node_path,
            str(partition.major),
            str(partition.minor),
        ),
        timeout,
    )
    stat_payload = text_exchange(
        host,
        port,
        f"stat_{partition.devname}",
        ("stat", partition.node_path),
        timeout,
    )
    _parse_node_stat_identity(stat_payload, partition)


def device_sha256(
    host: str, port: int, partition: Partition, timeout: float, phase: str
) -> str:
    evidence = f"sha256_{phase}_{partition.devname}"
    payload = parse_toybox_payload(
        run_toybox(
            host,
            port,
            evidence,
            ("sha256sum", partition.node_path),
            timeout,
        ),
        evidence,
    )
    matches = SHA256_LINE_RE.findall(payload)
    expected_path = partition.node_path.encode("ascii")
    hashes = [digest.decode("ascii") for digest, path in matches if path == expected_path]
    if len(hashes) != 1:
        raise ValueError(
            f"expected one device SHA-256 for {partition.node_path}, got {len(hashes)}"
        )
    return hashes[0]


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_initial_json(path: Path, value: object, mode: int = 0o600) -> bytes:
    """Claim a final journal path exactly once before any bridge contact."""

    data = json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("initial partition-capture journal made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        # Leave the final path in place if a host failure occurs after O_EXCL;
        # its existence is the ownership/no-replay signal for this experiment.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    fsync_directory(path.parent)
    return data


def _atomic_replace_json(path: Path, value: object, mode: int = 0o600) -> bytes:
    """Durably update the already-owned arbitration journal."""

    data = json_bytes(value)
    temporary = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return data


def _publish_arbitration_incident(
    manifest_path: Path,
    journal_path: Path,
    journal: dict[str, object],
    error: BaseException,
) -> None:
    """Retain a redacted incident when binding/arbitration stops the run."""

    journal.update(
        {
            "status": "ARBITRATION_FAILED",
            "error": f"{type(error).__name__}: {error}",
            "partition_writes": False,
            "completed_utc": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
        }
    )
    _atomic_replace_json(journal_path, journal)
    incident = {
        "schema": "sdm855-memory-boundary-live-firmware-capture-manifest-v1",
        "experiment_id": journal.get("experiment_id"),
        "started_utc": journal.get("started_utc"),
        "completed_utc": journal.get("completed_utc"),
        "status": journal["status"],
        "classification": journal["status"],
        "partition_writes": False,
        "arbitration_journal": journal_path.name,
        "stophud": journal.get("stophud"),
        "stophud_attempts": journal.get("stophud_attempts", []),
        "stophud_frames": journal.get("stophud_frames", []),
        "error": journal["error"],
        "redaction": {
            "serial_identity": "omitted",
            "raw_cmdline": "omitted",
            "raw_transcript": "omitted",
        },
    }
    try:
        write_new(manifest_path, json_bytes(incident), 0o644)
    except FileExistsError:
        pass


def capture_partition(
    host: str,
    port: int,
    partition: Partition,
    private_dir: Path,
    command_timeout: float,
    capture_timeout: float,
    *,
    before_mutation: MutationBinding | None = None,
    start_sector: int | None = None,
) -> dict[str, object]:
    if partition.partname == PARAM_PARTNAME:
        validate_param_partition(partition, start_sector)
    partial_path = private_dir / f"{partition.artifact_id}.bin.partial"
    final_path = private_dir / f"{partition.artifact_id}.bin"
    if partial_path.exists() or final_path.exists():
        raise FileExistsError(f"capture output already exists for {partition.artifact_id}")

    try:
        create_and_validate_node(
            host,
            port,
            partition,
            command_timeout,
            before_mutation=before_mutation,
        )
        before = device_sha256(host, port, partition, command_timeout, "before")
        end_fields, payload = binary_exchange(
            host,
            port,
            partition.node_path,
            partition.byte_size,
            capture_timeout,
        )
        host_hash = sha256(payload)
        write_new(partial_path, payload, 0o600)
        after = device_sha256(host, port, partition, command_timeout, "after")
        if before != host_hash or after != host_hash:
            raise ValueError(
                f"independent hash mismatch for {partition.artifact_id}: "
                f"before={before} host={host_hash} after={after}"
            )
        os.rename(partial_path, final_path)
        fsync_directory(private_dir)
        historical = HISTORICAL_SHA256.get(partition.devname)
        return {
            **asdict(partition),
            "artifact_id": partition.artifact_id,
            "private_filename": final_path.name,
            "sha256": host_hash,
            "device_sha256_before": before,
            "device_sha256_after": after,
            "historical_sha256_2026_06_02": historical,
            "historical_match": historical == host_hash if historical else None,
            "a90p1_end": end_fields,
            **(
                {"start_sector": start_sector}
                if partition.partname == PARAM_PARTNAME
                else {}
            ),
        }
    finally:
        # Fixed-path cleanup is idempotent and must run even if frame parsing
        # fails immediately after mknodb succeeds.
        remove_node(
            host,
            port,
            partition,
            command_timeout,
            before_mutation=before_mutation,
        )


def _validate_param_partition(partition: Partition, start_sector: int | None) -> None:
    """Require the complete pinned param geometry when that helper is used."""

    if partition.partname != PARAM_PARTNAME or partition.devname != PARAM_DEVNAME:
        raise ValueError("param capture requires exact sda10/PARTNAME=param")
    if type(start_sector) is not int:
        raise ValueError("param start sector is not an exact integer")
    validate_partition(partition)
    if (partition.major, partition.minor) != (PARAM_MAJOR, PARAM_MINOR):
        raise ValueError("param major/minor differs from the pinned geometry")
    if partition.sectors != PARAM_SECTORS or partition.byte_size != PARAM_PARTITION_BYTES:
        raise ValueError("param size differs from the pinned 10 MiB geometry")
    if partition.read_only != PARAM_READ_ONLY:
        raise ValueError("param read-only state differs from the pinned zero value")
    if partition.logical_block_size != PARAM_LOGICAL_BLOCK_SIZE:
        raise ValueError("param logical block size differs from the pinned 4096 value")
    if start_sector != PARAM_START_SECTOR:
        raise ValueError(
            f"param start sector differs from the pinned {PARAM_START_SECTOR} value"
        )


validate_param_partition = _validate_param_partition


def _validate_fixed_identity(
    version_payload: bytes, cmdline_payload: bytes
) -> dict[str, str]:
    """Validate the exact live V2321/model/bootloader and return observed data."""

    # Imported lazily to avoid the param producer's import of this helper
    # forming a module-initialization cycle.
    from tools.a90_param_capture import parse_cmdline, validate_runtime

    cmdline = parse_cmdline(cmdline_payload)
    validate_runtime(version_payload, cmdline)
    version_text = version_payload.decode("ascii", errors="strict").replace("\r\n", "\n")
    if version_text.endswith("\n"):
        version_text = version_text[:-1]
    lines = version_text.split("\n")
    runtime_lines = [line for line in lines if line.startswith("A90 Linux init ")]
    if runtime_lines != [f"A90 Linux init 0.9.285 ({TARGET_RUNTIME})"]:
        raise ValueError("returned V2321 runtime banner is not exact")
    build_lines = [line for line in lines if line.startswith("version: ")]
    kernel_lines = [line for line in lines if line.startswith("kernel: ")]
    if build_lines != [f"version: 0.9.285 build={TARGET_RUNTIME}"]:
        raise ValueError("returned V2321 version/build identity is not exact")
    if kernel_lines != [f"kernel: {TARGET_KERNEL}"]:
        raise ValueError("returned V2321 kernel identity is not exact")
    canonical_build = build_lines[0].removeprefix("version: 0.9.285 build=")
    kernel = kernel_lines[0].removeprefix("kernel: ")
    return {
        "model": cmdline["androidboot.em.model"],
        "bootloader": cmdline["androidboot.bootloader"],
        "runtime": canonical_build,
        "kernel": kernel,
        "soc": TARGET_SOC,
    }


def _validate_fixed_endpoint(args: argparse.Namespace) -> None:
    host = getattr(args, "host", BRIDGE_HOST)
    port = getattr(args, "port", BRIDGE_PORT)
    if host != BRIDGE_HOST or port != BRIDGE_PORT:
        raise ValueError("collector only accepts the pinned 127.0.0.1:54321 bridge")


def _validate_output_attrs(args: argparse.Namespace) -> None:
    """Reject injected output namespaces; the standalone owner is fixed-root."""

    if hasattr(args, "output_root"):
        supplied_value = getattr(args, "output_root")
        if not isinstance(supplied_value, (str, os.PathLike)):
            raise ValueError("standalone capture output root is fixed to REPO_ROOT")
        supplied = Path(supplied_value).resolve()
        if supplied != Path(REPO_ROOT).resolve():
            raise ValueError("standalone capture output root is fixed to REPO_ROOT")


def _bind_fixed_bridge() -> Mapping[str, object]:
    # Binding is intentionally explicit in collect/main, never at import.
    binding = validate_bridge_binding()
    if not isinstance(binding, Mapping):
        raise ValueError("fixed bridge binding is not an object")
    listener = binding.get("listener")
    if isinstance(listener, Mapping) and (
        listener.get("host") != BRIDGE_HOST or listener.get("port") != BRIDGE_PORT
    ):
        raise ValueError("fixed bridge binding listener differs from 127.0.0.1:54321")
    return binding


def _bridge_bindings_match(
    initial: Mapping[str, object], current: Mapping[str, object]
) -> bool:
    ignored = {"validated_utc"}
    keys = (set(initial) | set(current)) - ignored
    return all(initial.get(key) == current.get(key) for key in keys)


def _fresh_bridge_binding(initial: Mapping[str, object], label: str) -> Mapping[str, object]:
    current = revalidate_bridge_binding(initial)
    if not isinstance(current, Mapping) or not _bridge_bindings_match(initial, current):
        raise RuntimeError(f"fixed bridge binding drifted before {label}")
    return current


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("invalid experiment ID")
    if getattr(args, "execute", False) is not True:
        raise ValueError("persistent partition capture requires explicit --execute")
    _validate_fixed_endpoint(args)
    _validate_output_attrs(args)
    command_timeout = validate_timeout(
        args.command_timeout, "command-timeout", MAX_COMMAND_TIMEOUT
    )
    capture_timeout = validate_timeout(
        args.capture_timeout, "capture-timeout", MAX_CAPTURE_TIMEOUT
    )
    root = Path(REPO_ROOT).resolve()
    private_dir = root / "evidence" / "private" / args.experiment_id
    manifest_path = root / "evidence" / "manifests" / f"{args.experiment_id}.manifest.json"
    journal_path = private_dir / PARTITION_CAPTURE_JOURNAL_NAME
    if private_dir.exists() or manifest_path.exists() or journal_path.exists():
        raise FileExistsError("experiment output already exists")
    private_dir.mkdir(parents=True, mode=0o700)
    os.chmod(private_dir, 0o700)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    stophud_frames: list[dict[str, object]] = []
    journal: dict[str, object] = {
        "schema": PARTITION_CAPTURE_JOURNAL_SCHEMA,
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "status": "ARBITRATION_INTENT_DURABLE",
        "bridge_binding": None,
        "stophud": None,
        "stophud_attempts": [],
        "stophud_frames": stophud_frames,
        "partition_writes": False,
        "error": None,
    }
    _write_initial_json(journal_path, journal)

    def persist_stophud(attempts: list[dict[str, object]]) -> None:
        journal["stophud_attempts"] = attempts
        journal["stophud_frames"] = stophud_frames
        _atomic_replace_json(journal_path, journal)

    try:
        # Bind the exact operator-owned bridge only after the durable intent,
        # then rebind immediately adjacent to the first stateful command.
        bridge_binding = _bind_fixed_bridge()
        journal["bridge_binding"] = dict(bridge_binding)
        journal["status"] = "BRIDGE_BOUND"
        _atomic_replace_json(journal_path, journal)
        _fresh_bridge_binding(bridge_binding, "stophud")

        def stophud_exchange(host, port, command, timeout, **kwargs):
            # Revalidate directly before every bounded stophud retry.  A
            # busy response may be retried only while the exact bridge remains
            # continuously bound.
            _fresh_bridge_binding(bridge_binding, "stophud_attempt")
            return exchange(host, port, command, timeout, **kwargs)

        stophud = run_stophud(
            BRIDGE_HOST,
            BRIDGE_PORT,
            command_timeout,
            stophud_exchange,
            frame_records=stophud_frames,
            persist=persist_stophud,
        )
        journal["stophud"] = stophud
        journal["status"] = "PREFLIGHT"
        _atomic_replace_json(journal_path, journal)
    except BaseException as exc:
        _publish_arbitration_incident(manifest_path, journal_path, journal, exc)
        raise

    version_payload = text_exchange(
        BRIDGE_HOST, BRIDGE_PORT, "version", ("version",), command_timeout
    )
    cmdline_payload = text_exchange(
        BRIDGE_HOST,
        BRIDGE_PORT,
        "proc_cmdline",
        ("cat", "/proc/cmdline"),
        command_timeout,
    )
    observed_target = _validate_fixed_identity(version_payload, cmdline_payload)
    toybox_stat = text_exchange(
        BRIDGE_HOST, BRIDGE_PORT, "toybox_stat", ("stat", TOYBOX), command_timeout
    )
    requested_partnames = list(getattr(args, "partname", []))
    partitions = discover_partitions(BRIDGE_HOST, BRIDGE_PORT, command_timeout)
    param_start_sectors: dict[str, int] = {}
    if PARAM_PARTNAME in requested_partnames:
        param_partition, param_start = discover_param_partition(
            BRIDGE_HOST, BRIDGE_PORT, command_timeout
        )
        partitions.append(param_partition)
        partitions.sort(key=lambda item: (item.partname, item.devname))
        param_start_sectors[param_partition.devname] = param_start
    selected = select_partitions(partitions, requested_partnames)
    def before_mutation(label: str) -> Mapping[str, object]:
        return _fresh_bridge_binding(bridge_binding, label)

    records = []
    for partition in selected:
        records.append(
            capture_partition(
                BRIDGE_HOST,
                BRIDGE_PORT,
                partition,
                private_dir,
                command_timeout,
                capture_timeout,
                before_mutation=before_mutation,
                start_sector=param_start_sectors.get(partition.devname),
            )
        )

    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    private_metadata = {
        "schema": "sdm855-memory-boundary-live-firmware-capture-private-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": observed_target["model"],
        "soc": observed_target["soc"],
        "bootloader": observed_target["bootloader"],
        "target_bootloader": observed_target["bootloader"],
        "target": observed_target,
        "bridge_binding": dict(bridge_binding),
        "arbitration_journal": journal_path.name,
        "stophud": stophud,
        "stophud_frames": stophud_frames,
        "version_payload": version_payload.decode("utf-8", errors="strict"),
        "cmdline_payload": cmdline_payload.decode("utf-8", errors="strict"),
        "toybox_stat_payload": toybox_stat.decode("utf-8", errors="strict"),
        "discovered_allowlisted_partitions": [asdict(item) for item in partitions],
        "records": records,
        "device_writes": False,
        "filesystem_only_mutations": [
            "temporary block-device node creation under /dev",
            "temporary block-device node removal under /dev",
        ],
    }
    private_metadata_path = private_dir / "capture-metadata.json"
    write_new(private_metadata_path, json_bytes(private_metadata), 0o600)

    public_records = []
    for record in records:
        public_records.append(
            {
                key: value
                for key, value in record.items()
                if key
                in {
                    "partname",
                    "devname",
                    "major",
                    "minor",
                    "sectors",
                    "byte_size",
                    "read_only",
                    "logical_block_size",
                    "start_sector",
                    "artifact_id",
                    "sha256",
                    "device_sha256_before",
                    "device_sha256_after",
                    "historical_sha256_2026_06_02",
                    "historical_match",
                }
            }
        )
    manifest = {
        "schema": "sdm855-memory-boundary-live-firmware-capture-manifest-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target": observed_target,
        "arbitration_journal": journal_path.name,
        "stophud_accepted": bool(stophud.get("accepted")),
        "stophud_busy_retries": stophud.get("busy_retries", 0),
        "target_model": observed_target["model"],
        "soc": observed_target["soc"],
        "bootloader": observed_target["bootloader"],
        "runtime": observed_target["runtime"],
        "kernel": observed_target["kernel"],
        "capture_method": "sysfs-bound temporary block node; device sha256sum; A90P1 cat; device sha256sum",
        "partition_writes": False,
        "raw_artifacts_git_ignored": True,
        "records": public_records,
        "limitations": [
            "Partition identity is live GPT/sysfs identity; active boot slot is not inferred.",
            "Raw proprietary firmware remains private and is excluded from Git.",
        ],
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    journal.update(
        {
            "status": "COMPLETE",
            "completed_utc": completed,
            "stophud": stophud,
            "stophud_attempts": stophud.get("attempts", []),
            "stophud_frames": stophud_frames,
            "records": records,
        }
    )
    _atomic_replace_json(journal_path, journal)
    return private_metadata_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--command-timeout", type=float, default=30.0)
    parser.add_argument("--capture-timeout", type=float, default=180.0)
    parser.add_argument(
        "--partname",
        action="append",
        choices=ALLOWED_PARTNAMES,
        default=[],
        help="capture only this fixed partition name; repeatable; default is all discovered allowlisted names",
    )
    parser.add_argument("--execute", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    private_metadata, manifest = collect(args)
    print(f"private metadata: {private_metadata}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
