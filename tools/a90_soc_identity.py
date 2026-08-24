#!/usr/bin/env python3
"""Capture the fixed read-only A90 SoC fields needed to select an XBL DCB.

The collector only speaks A90P1 through a loopback bridge and only issues the
fixed ``version``/``cat`` commands below.  It does not read MMIO or mutate the
target.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new


SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
DECIMAL_RE = re.compile(r"[0-9]+\Z")
HW_PLATFORM_IDS = {
    "UNKNOWN": 0,
    "SURF": 1,
    "FFA": 2,
    "FLUID": 3,
    "SVLTE_FFA": 4,
    "SLVTE_SURF": 5,
    "MDM_MTP_NO_DISPLAY": 7,
    "MTP": 8,
    "LIQUID": 9,
    "DRAGON": 10,
    "QRD": 11,
    "HRD": 13,
    "DTV": 14,
    "RUMI": 15,
    "RCM": 21,
    "STP": 23,
    "SBC": 24,
    "ADP": 25,
    "TTP": 30,
    "HDK": 31,
    "IOT": 32,
    "IDP": 34,
}
KNOWN_DCB_FILENAMES = {
    "/6003_0100_1_dcb.bin",
    "/6003_0100_0_dcb.bin",
    "/6003_0200_1_dcb.bin",
    "/6003_0200_0_dcb.bin",
}

COMMANDS = (
    Command("version", ("version",)),
    Command("soc_id", ("cat", "/sys/devices/soc0/soc_id")),
    Command("revision", ("cat", "/sys/devices/soc0/revision")),
    Command("raw_id", ("cat", "/sys/devices/soc0/raw_id")),
    Command("raw_version", ("cat", "/sys/devices/soc0/raw_version")),
    Command("hw_platform", ("cat", "/sys/devices/soc0/hw_platform")),
    Command(
        "platform_subtype",
        ("cat", "/sys/devices/soc0/platform_subtype"),
    ),
    Command("proc_meminfo", ("cat", "/proc/meminfo")),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean_text(payload: bytes, label: str) -> str:
    value = payload.decode("ascii", errors="strict").strip()
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{label} is not a single nonempty text value")
    return value


def parse_decimal(value: str, label: str) -> int:
    if DECIMAL_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not decimal: {value!r}")
    return int(value, 10)


def parse_memtotal_kib(payload: bytes) -> int:
    text = payload.decode("ascii", errors="strict")
    matches = re.findall(r"(?m)^MemTotal:\s+([0-9]+)\s+kB\s*$", text)
    if len(matches) != 1:
        raise ValueError("/proc/meminfo does not contain one MemTotal field")
    return int(matches[0], 10)


def derive_selector(values: dict[str, str]) -> dict[str, object]:
    raw_id = parse_decimal(values["raw_id"], "raw_id")
    raw_version = parse_decimal(values["raw_version"], "raw_version")
    platform_name = values["hw_platform"].upper()
    if platform_name not in HW_PLATFORM_IDS:
        raise ValueError(f"unrecognized hw_platform value: {values['hw_platform']!r}")
    platform_id = HW_PLATFORM_IDS[platform_name]
    physical_platform = int(platform_id != 0x0F)
    hardware_id = raw_id & 0xFFFF
    hardware_version = raw_version & 0xFF00
    filename = (
        f"/{hardware_id:04X}_{hardware_version:04X}_"
        f"{physical_platform:d}_dcb.bin"
    )
    present_in_exact_cfgl = filename in KNOWN_DCB_FILENAMES
    return {
        "hardware_id": f"0x{hardware_id:04x}",
        "hardware_version": f"0x{hardware_version:04x}",
        "physical_platform": physical_platform,
        "hw_platform_id": f"0x{platform_id:x}",
        "dcb_filename_candidate": filename,
        "present_in_exact_cfgl": present_in_exact_cfgl,
        "status": "SUPPORTED" if present_in_exact_cfgl else "UNKNOWN",
        "qualification": (
            "The exact kernel exposes raw SoC fields from SMEM, while exact XBL "
            "constructs the filename from 0x01fc8000 and platform type. A direct "
            "source trace proving those producers are identical is still pending."
        ),
    }


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("collector only accepts a loopback bridge")

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    raw_records: list[dict[str, object]] = []
    public_records: list[dict[str, object]] = []
    values: dict[str, str] = {}
    memtotal_kib: int | None = None

    for command in COMMANDS:
        frame = exchange(args.host, args.port, command, args.timeout)
        record = {
            "evidence_id": command.evidence_id,
            "argv": list(command.argv),
            "begin": frame.begin,
            "end": frame.end,
            "payload_base64": base64.b64encode(frame.payload).decode("ascii"),
            "payload_size": len(frame.payload),
            "payload_sha256": sha256(frame.payload),
            "transcript_size": len(frame.transcript),
            "transcript_sha256": sha256(frame.transcript),
        }
        raw_records.append(record)
        public = {
            "evidence_id": command.evidence_id,
            "command": " ".join(command.argv),
            "payload_size": len(frame.payload),
            "payload_sha256": record["payload_sha256"],
            "rc": int(frame.end["rc"], 0),
            "status": frame.end["status"],
        }
        if command.evidence_id in {
            "soc_id",
            "revision",
            "raw_id",
            "raw_version",
            "hw_platform",
            "platform_subtype",
        }:
            value = clean_text(frame.payload, command.evidence_id)
            values[command.evidence_id] = value
            public["value"] = value
        elif command.evidence_id == "proc_meminfo":
            memtotal_kib = parse_memtotal_kib(frame.payload)
            public["memtotal_kib"] = memtotal_kib
        public_records.append(public)

    selector = derive_selector(values)
    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    raw = {
        "schema": "sdm855-a90-soc-identity-readonly-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target": {"model": "SM-A908N", "soc": "SM8150"},
        "safety": {
            "transport": "operator-pinned loopback A90P1 bridge",
            "device_commands": "fixed version/cat allowlist",
            "device_writes": False,
            "mmio_access": False,
            "automatic_retries": False,
        },
        "records": raw_records,
        "values": values,
        "memtotal_kib": memtotal_kib,
        "dcb_selector_candidate": selector,
    }
    raw_bytes = json_bytes(raw)
    manifest = {
        "schema": "sdm855-a90-soc-identity-readonly-manifest-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "device_writes": False,
        "records": public_records,
        "dcb_selector_candidate": selector,
        "raw_snapshot_sha256": sha256(raw_bytes),
        "raw_snapshot_size": len(raw_bytes),
        "claim_boundary": (
            "SUPPORTED live DCB selector candidate; direct identity between the "
            "SMEM raw fields and XBL's 0x01fc8000 read remains to be proved"
        ),
    }

    root = Path(args.output_root).resolve()
    raw_path = root / "evidence/private" / f"{args.experiment_id}.json"
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    write_new(raw_path, raw_bytes, 0o600)
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return raw_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument(
        "--output-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    raw_path, manifest_path = collect(args)
    print(json.dumps({"raw": str(raw_path), "manifest": str(manifest_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
