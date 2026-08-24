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
import os
import re
import socket
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, parse_fields, write_new
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, parse_fields, write_new


SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
BEGIN_LINE_RE = re.compile(rb"A90P1 BEGIN (?P<fields>[^\r\n]+)\r?\n")
END_AFTER_PAYLOAD_RE = re.compile(
    rb"^\r\n\[done\] cat \([0-9]+ms\)\r\n"
    rb"A90P1 END (?P<fields>[^\r\n]+)\r\n"
    rb"a90:/# ?(?:\r?\n)?$"
)
SHA256_LINE_RE = re.compile(rb"(?m)^([0-9a-f]{64})  (/dev/[A-Za-z0-9_.-]+)\r?$")

SECTOR_BYTES = 512
MAX_PARTITION_BYTES = 8 * 1024 * 1024
TOYBOX = "/bin/toybox"
DEVICE_NODE_PREFIX = "/dev/sdm855_mblab_"

PARTITION_SIZE = {
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


def validate_partition(partition: Partition) -> None:
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
    deadline = time.monotonic() + timeout
    data = bytearray()
    payload_end: int | None = None
    with socket.create_connection((host, port), timeout=min(timeout, 3.0)) as sock:
        sock.settimeout(0.25)
        sock.sendall(b"\ncmdv1 cat " + node_path.encode("ascii") + b"\n")
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(262144)
            except socket.timeout:
                continue
            if not chunk:
                break
            data.extend(chunk)
            if payload_end is None:
                for match in BEGIN_LINE_RE.finditer(data):
                    fields = parse_fields(match.group("fields"))
                    if fields.get("cmd") == "cat":
                        payload_end = match.end() + expected_size
                        break
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


def remove_node(host: str, port: int, partition: Partition, timeout: float) -> None:
    run_toybox(
        host,
        port,
        f"cleanup_{partition.devname}",
        ("rm", "-f", partition.node_path),
        timeout,
    )


def create_and_validate_node(
    host: str, port: int, partition: Partition, timeout: float
) -> None:
    remove_node(host, port, partition, timeout)
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
    ).decode("ascii", errors="strict")
    if f"rdev={partition.major}:{partition.minor}" not in stat_payload:
        raise ValueError(f"temporary node rdev mismatch: {stat_payload!r}")


def device_sha256(
    host: str, port: int, partition: Partition, timeout: float, phase: str
) -> str:
    payload = run_toybox(
        host,
        port,
        f"sha256_{phase}_{partition.devname}",
        ("sha256sum", partition.node_path),
        timeout,
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


def capture_partition(
    host: str,
    port: int,
    partition: Partition,
    private_dir: Path,
    command_timeout: float,
    capture_timeout: float,
) -> dict[str, object]:
    partial_path = private_dir / f"{partition.artifact_id}.bin.partial"
    final_path = private_dir / f"{partition.artifact_id}.bin"
    if partial_path.exists() or final_path.exists():
        raise FileExistsError(f"capture output already exists for {partition.artifact_id}")

    try:
        create_and_validate_node(host, port, partition, command_timeout)
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
        }
    finally:
        # Fixed-path cleanup is idempotent and must run even if frame parsing
        # fails immediately after mknodb succeeds.
        remove_node(host, port, partition, command_timeout)


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("invalid experiment ID")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("collector only accepts a loopback bridge")
    root = Path(args.output_root).resolve()
    private_dir = root / "evidence" / "private" / args.experiment_id
    manifest_path = root / "evidence" / "manifests" / f"{args.experiment_id}.manifest.json"
    if private_dir.exists() or manifest_path.exists():
        raise FileExistsError("experiment output already exists")
    private_dir.mkdir(parents=True, mode=0o700)
    os.chmod(private_dir, 0o700)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    version_payload = text_exchange(
        args.host, args.port, "version", ("version",), args.command_timeout
    )
    toybox_stat = text_exchange(
        args.host, args.port, "toybox_stat", ("stat", TOYBOX), args.command_timeout
    )
    partitions = discover_partitions(args.host, args.port, args.command_timeout)
    selected = select_partitions(partitions, args.partname)
    records = []
    for partition in selected:
        records.append(
            capture_partition(
                args.host,
                args.port,
                partition,
                private_dir,
                args.command_timeout,
                args.capture_timeout,
            )
        )

    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    private_metadata = {
        "schema": "sdm855-memory-boundary-live-firmware-capture-private-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "version_payload": version_payload.decode("utf-8", errors="strict"),
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
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "runtime": "v2321-usb-clean-identity-rodata",
        "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
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
    return private_metadata_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--command-timeout", type=float, default=30.0)
    parser.add_argument("--capture-timeout", type=float, default=180.0)
    parser.add_argument(
        "--partname",
        action="append",
        choices=ALLOWED_PARTNAMES,
        default=[],
        help="capture only this fixed partition name; repeatable; default is all discovered allowlisted names",
    )
    parser.add_argument(
        "--discover-only",
        action="store_true",
        help="print validated allowlisted live metadata without creating nodes or output files",
    )
    parser.add_argument("--output-root", default=str(Path(__file__).resolve().parents[1]))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.discover_only:
        if args.host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("collector only accepts a loopback bridge")
        partitions = discover_partitions(args.host, args.port, args.command_timeout)
        selected = select_partitions(partitions, args.partname)
        print(json.dumps([asdict(item) for item in selected], indent=2, sort_keys=True))
        return 0
    private_metadata, manifest = collect(args)
    print(f"private metadata: {private_metadata}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
