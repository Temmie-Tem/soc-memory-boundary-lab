#!/usr/bin/env python3
"""Capture the exact A90 ``param`` partition as a rollback artifact.

This collector is deliberately narrower than the firmware collector.  It only
accepts the operator-pinned loopback A90P1 bridge, requires the exact live
SM-A908N runtime identity, resolves exactly ``sda10``/``PARTNAME=param``, and
captures exactly 10 MiB.  The target is hashed before and after the transfer;
the host copy must match both hashes.  No partition data is written.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import struct
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from tools.a90_partition_capture import (
        Partition,
        binary_exchange,
        create_and_validate_node,
        device_sha256,
        fsync_directory,
        parse_decimal,
        parse_uevent,
        remove_node,
        sha256,
        text_exchange,
    )
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new  # type: ignore
    from a90_partition_capture import (  # type: ignore
        Partition,
        binary_exchange,
        create_and_validate_node,
        device_sha256,
        fsync_directory,
        parse_decimal,
        parse_uevent,
        remove_node,
        sha256,
        text_exchange,
    )


SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
CMDLINE_TOKEN_RE = re.compile(r"(?:^| )(?P<key>[^ =]+)=(?P<value>[^ ]*)")

TARGET_MODEL = "SM-A908N"
TARGET_SOC = "SM8150"
TARGET_BOOTLOADER = "A908NKSU5EWA3"
TARGET_RUNTIME = "v2321-usb-clean-identity-rodata"
TARGET_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"

PARAM_DEVNAME = "sda10"
PARAM_PARTNAME = "param"
PARAM_PARTITION_BYTES = 0xA00000
PARAM_SECTORS = PARAM_PARTITION_BYTES // 512
PARAM_RECORD_OFFSET = PARAM_PARTITION_BYTES - 0x100000
PARAM_DEBUG_OFFSET = PARAM_RECORD_OFFSET + 0x000
PARAM_FORCE_UPLOAD_OFFSET = PARAM_RECORD_OFFSET + 0x3F4
PARAM_FMM_LOCK_OFFSET = PARAM_RECORD_OFFSET + 0x3FC
PARAM_DUMP_SINK_OFFSET = PARAM_RECORD_OFFSET + 0x400

KERNEL_DEBUG_LOW = 0x574F4C44
KERNEL_DEBUG_MID = 0x44494D44
KERNEL_DEBUG_HIGH = 0x47494844
FMM_LOCK_MAGIC = 0x464D4F4E
DUMP_SINK_SDCARD = 0x73646364
DUMP_SINK_BOOTDEV = 0x42544456

FIELD_OFFSETS = {
    "debuglevel": PARAM_DEBUG_OFFSET,
    "force_upload_flag": PARAM_FORCE_UPLOAD_OFFSET,
    "FMM_lock": PARAM_FMM_LOCK_OFFSET,
    "dump_sink": PARAM_DUMP_SINK_OFFSET,
}


def parse_cmdline(payload: bytes) -> dict[str, str]:
    text = payload.decode("ascii", errors="strict").strip()
    result: dict[str, str] = {}
    for match in CMDLINE_TOKEN_RE.finditer(text):
        key = match.group("key")
        if key in result:
            raise ValueError(f"duplicate cmdline key: {key}")
        result[key] = match.group("value")
    return result


def validate_runtime(version_payload: bytes, cmdline: dict[str, str]) -> None:
    version = version_payload.decode("ascii", errors="strict")
    required = (
        f"version: 0.9.285 build={TARGET_RUNTIME}",
        f"kernel: {TARGET_KERNEL}",
    )
    missing = [line for line in required if line not in version]
    if missing:
        raise ValueError(f"A90 runtime identity mismatch: {missing}")
    if cmdline.get("androidboot.em.model") != TARGET_MODEL:
        raise ValueError("live cmdline is not bound to SM-A908N")
    if cmdline.get("androidboot.bootloader") != TARGET_BOOTLOADER:
        raise ValueError("live bootloader build differs from the exact target")


def discover_param(host: str, port: int, timeout: float) -> tuple[Partition, int]:
    prefix = f"/sys/class/block/{PARAM_DEVNAME}"
    uevent = parse_uevent(
        text_exchange(host, port, "param_uevent", ("cat", f"{prefix}/uevent"), timeout)
    )
    required = {
        "DEVNAME": PARAM_DEVNAME,
        "DEVTYPE": "partition",
        "PARTNAME": PARAM_PARTNAME,
        "PARTN": "10",
    }
    if any(uevent.get(key) != value for key, value in required.items()):
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
        partname=uevent["PARTNAME"],
        devname=uevent["DEVNAME"],
        major=int(uevent["MAJOR"], 10),
        minor=int(uevent["MINOR"], 10),
        sectors=sectors,
        byte_size=sectors * 512,
        read_only=read_only,
        logical_block_size=logical_block_size,
    )
    validate_param_partition(partition, start_sector)
    return partition, start_sector


def validate_param_partition(partition: Partition, start_sector: int) -> None:
    if partition.partname != PARAM_PARTNAME or partition.devname != PARAM_DEVNAME:
        raise ValueError("partition is not exact sda10/PARTNAME=param")
    if (partition.major, partition.minor) != (8, 10):
        raise ValueError("param major/minor differs from the exact live binding")
    if partition.sectors != PARAM_SECTORS or partition.byte_size != PARAM_PARTITION_BYTES:
        raise ValueError("param partition is not exactly 10 MiB")
    if partition.read_only != 0:
        raise ValueError("param live sysfs read-only state changed from zero")
    if partition.logical_block_size != 4096:
        raise ValueError("param parent logical block size is not 4096")
    if start_sector <= 0 or start_sector % 8:
        raise ValueError("param start is not a positive 4096-byte-aligned sector")


def decode_fields(data: bytes) -> dict[str, object]:
    if len(data) != PARAM_PARTITION_BYTES:
        raise ValueError(f"param image size {len(data)} != {PARAM_PARTITION_BYTES}")
    values = {
        name: struct.unpack_from("<I", data, offset)[0]
        for name, offset in FIELD_OFFSETS.items()
    }
    debug_labels = {
        KERNEL_DEBUG_LOW: "LOW",
        KERNEL_DEBUG_MID: "MID",
        KERNEL_DEBUG_HIGH: "HIGH",
    }
    sink_labels = {
        0: "USB_DEFAULT",
        DUMP_SINK_SDCARD: "SDCARD",
        DUMP_SINK_BOOTDEV: "BOOTDEV_INTERNAL",
    }
    return {
        name: {
            "partition_offset": f"0x{FIELD_OFFSETS[name]:06x}",
            "record_offset": f"0x{FIELD_OFFSETS[name] - PARAM_RECORD_OFFSET:03x}",
            "value": f"0x{value:08x}",
            "label": (
                debug_labels.get(value, "UNKNOWN")
                if name == "debuglevel"
                else ("LOCKED" if value == FMM_LOCK_MAGIC else "NOT_LOCK_MAGIC")
                if name == "FMM_lock"
                else sink_labels.get(value, "USB_DEFAULT_BRANCH_OTHER")
                if name == "dump_sink"
                else "ENABLED" if value == 5 else "NOT_ENABLED_VALUE_5"
            ),
        }
        for name, value in values.items()
    }


def _cmdline_relevant(cmdline: dict[str, str]) -> dict[str, str | None]:
    keys = (
        "androidboot.em.model",
        "androidboot.bootloader",
        "androidboot.debug_level",
        "androidboot.force_upload",
        "sec_debug.dump_sink",
        "androidboot.upload_offset",
    )
    return {key: cmdline.get(key) for key in keys}


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("invalid experiment ID")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("collector only accepts a loopback bridge")

    root = args.output_root.resolve()
    private_dir = root / "evidence/private" / args.experiment_id
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    if private_dir.exists() or manifest_path.exists():
        raise FileExistsError("experiment output already exists")
    private_dir.mkdir(parents=True, mode=0o700)
    os.chmod(private_dir, 0o700)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    version_frame = exchange(
        args.host, args.port, Command("version", ("version",)), args.command_timeout
    )
    cmdline_frame = exchange(
        args.host,
        args.port,
        Command("proc_cmdline", ("cat", "/proc/cmdline")),
        args.command_timeout,
    )
    cmdline = parse_cmdline(cmdline_frame.payload)
    validate_runtime(version_frame.payload, cmdline)
    dload_frame = exchange(
        args.host,
        args.port,
        Command(
            "download_mode",
            ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
        ),
        args.command_timeout,
    )
    dload_value = dload_frame.payload.decode("ascii", errors="strict").strip()
    if dload_value != "1":
        raise ValueError(f"download_mode precondition is {dload_value!r}, not '1'")

    partition, start_sector = discover_param(
        args.host, args.port, args.command_timeout
    )
    partial_path = private_dir / "param--sda10.bin.partial"
    final_path = private_dir / "param--sda10.bin"
    try:
        create_and_validate_node(args.host, args.port, partition, args.command_timeout)
        before = device_sha256(
            args.host, args.port, partition, args.command_timeout, "before"
        )
        end_fields, payload = binary_exchange(
            args.host,
            args.port,
            partition.node_path,
            PARAM_PARTITION_BYTES,
            args.capture_timeout,
        )
        host_hash = sha256(payload)
        write_new(partial_path, payload, 0o600)
        after = device_sha256(
            args.host, args.port, partition, args.command_timeout, "after"
        )
        if before != host_hash or after != host_hash:
            raise ValueError(
                "independent param hash mismatch: "
                f"before={before} host={host_hash} after={after}"
            )
        os.rename(partial_path, final_path)
        fsync_directory(private_dir)
    finally:
        remove_node(args.host, args.port, partition, args.command_timeout)

    fields = decode_fields(payload)
    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    private_metadata = {
        "schema": "sdm855-a90-param-capture-private-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime_payload": version_frame.payload.decode("ascii", errors="strict"),
        "cmdline": cmdline,
        "download_mode": dload_value,
        "partition": {
            **partition.__dict__,
            "start_sector": start_sector,
            "node_path": partition.node_path,
        },
        "capture": {
            "private_filename": final_path.name,
            "size": len(payload),
            "sha256": host_hash,
            "device_sha256_before": before,
            "device_sha256_after": after,
            "a90p1_end": end_fields,
        },
        "decoded_gate_fields": fields,
        "partition_writes": False,
        "filesystem_only_mutations": [
            "temporary fixed block-device node creation under /dev",
            "temporary fixed block-device node removal under /dev",
        ],
    }
    private_metadata_path = private_dir / "capture-metadata.json"
    write_new(private_metadata_path, json_bytes(private_metadata), 0o600)

    manifest = {
        "schema": "sdm855-a90-param-capture-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
        "bootloader": TARGET_BOOTLOADER,
        "partition": {
            "partname": partition.partname,
            "devname": partition.devname,
            "major": partition.major,
            "minor": partition.minor,
            "sectors": partition.sectors,
            "byte_size": partition.byte_size,
            "start_sector": start_sector,
            "read_only": partition.read_only,
            "logical_block_size": partition.logical_block_size,
        },
        "capture": {
            "size": len(payload),
            "sha256": host_hash,
            "device_sha256_before": before,
            "device_sha256_after": after,
            "triple_hash_match": before == host_hash == after,
        },
        "decoded_gate_fields": fields,
        "cmdline_relevant": _cmdline_relevant(cmdline),
        "download_mode": dload_value,
        "classification": (
            "PARAM_CAPTURED_DEBUG_ONLY_PRECONDITIONS_MET"
            if fields["FMM_lock"]["label"] == "NOT_LOCK_MAGIC"
            and fields["dump_sink"]["label"] == "USB_DEFAULT"
            and dload_value == "1"
            else "PARAM_CAPTURED_REEVALUATION_REQUIRED"
        ),
        "partition_writes": False,
        "raw_artifact_git_ignored": True,
        "claims": {
            "PROVED": [
                "The exact live sda10/PARTNAME=param partition was captured byte-for-byte and matched independent device-before, host, and device-after SHA-256 values.",
                "The four XBL gate fields were decoded at exact source-backed offsets in the retained rollback artifact.",
            ],
            "UNKNOWN": [
                "No persistent state was changed, so post-change XBL behavior remains untested by this capture.",
            ],
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return private_metadata_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--command-timeout", type=float, default=45.0)
    parser.add_argument("--capture-timeout", type=float, default=240.0)
    parser.add_argument(
        "--output-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    private_metadata, manifest = collect(args)
    print(f"private metadata: {private_metadata}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
