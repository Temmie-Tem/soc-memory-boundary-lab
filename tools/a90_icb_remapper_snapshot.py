#!/usr/bin/env python3
"""Read the four exact XBL-programmed A90 ICB remapper windows.

No arbitrary address is accepted.  The default smoke reads only the four
control words.  ``--full`` reads the proved 32-bit layout-1 offsets 0x00..0x58.
Every read is a data-less Toybox ``devmem`` invocation through a pinned A90P1
loopback bridge; the collector never supplies a write value or retries.
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
VALUE_RE = re.compile(rb"(?:0[xX])?([0-9a-fA-F]{1,8})")
TOYBOX = "/bin/toybox"
REGISTER_BASES = (0x09248080, 0x092C8080, 0x09348080, 0x093C8080)
CONTROL_OFFSETS = (0,)
FULL_OFFSETS = tuple(range(0, 0x5C, 4))
SOURCE_MANIFEST_SHA256 = (
    "39469ac59ef0e3a2b9858b7435a4433def58d57407a4066da3854cfdd24409a5"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_u32(payload: bytes) -> int:
    cleaned = payload.strip()
    match = VALUE_RE.fullmatch(cleaned)
    if match is None:
        raise ValueError(f"devmem output is not one 32-bit hex value: {cleaned!r}")
    return int(match.group(1), 16)


def read_commands(full: bool) -> tuple[Command, ...]:
    offsets = FULL_OFFSETS if full else CONTROL_OFFSETS
    result = []
    for base_index, base in enumerate(REGISTER_BASES):
        for offset in offsets:
            address = base + offset
            result.append(
                Command(
                    f"icb{base_index}_off_{offset:02x}",
                    # Toybox devmem expresses WIDTH in bytes, so 4 is 32 bits.
                    ("run", TOYBOX, "devmem", f"0x{address:08x}", "4"),
                )
            )
    return tuple(result)


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("collector only accepts a loopback bridge")

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    commands = read_commands(args.full)
    raw_records: list[dict[str, object]] = []
    public_records: list[dict[str, object]] = []

    before = exchange(
        args.host, args.port, Command("version_before", ("version",)), args.timeout
    )
    raw_records.append(
        {
            "evidence_id": "version_before",
            "argv": ["version"],
            "payload_base64": base64.b64encode(before.payload).decode("ascii"),
            "payload_sha256": sha256(before.payload),
            "transcript_sha256": sha256(before.transcript),
            "begin": before.begin,
            "end": before.end,
        }
    )

    for command in commands:
        frame = exchange(args.host, args.port, command, args.timeout)
        value = parse_u32(frame.payload)
        address = int(command.argv[3], 16)
        base = next(item for item in REGISTER_BASES if item <= address <= item + 0x58)
        offset = address - base
        raw_records.append(
            {
                "evidence_id": command.evidence_id,
                "argv": list(command.argv),
                "payload_base64": base64.b64encode(frame.payload).decode("ascii"),
                "payload_sha256": sha256(frame.payload),
                "transcript_sha256": sha256(frame.transcript),
                "begin": frame.begin,
                "end": frame.end,
                "value": f"0x{value:08x}",
            }
        )
        public_records.append(
            {
                "evidence_id": command.evidence_id,
                "base": f"0x{base:08x}",
                "offset": f"0x{offset:02x}",
                "address": f"0x{address:08x}",
                "width_bits": 32,
                "value": f"0x{value:08x}",
                "payload_sha256": sha256(frame.payload),
                "rc": int(frame.end["rc"], 0),
                "status": frame.end["status"],
            }
        )

    after = exchange(
        args.host, args.port, Command("version_after", ("version",)), args.timeout
    )
    raw_records.append(
        {
            "evidence_id": "version_after",
            "argv": ["version"],
            "payload_base64": base64.b64encode(after.payload).decode("ascii"),
            "payload_sha256": sha256(after.payload),
            "transcript_sha256": sha256(after.transcript),
            "begin": after.begin,
            "end": after.end,
        }
    )
    if before.payload != after.payload:
        raise RuntimeError("runtime version changed across the MMIO read snapshot")

    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    mode = "full-layout1" if args.full else "control-smoke"
    raw = {
        "schema": "sdm855-a90-icb-remapper-readonly-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target": {"model": "SM-A908N", "soc": "SM8150"},
        "mode": mode,
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "safety": {
            "transport": "operator-pinned loopback A90P1 bridge",
            "device_commands": "version and fixed Toybox devmem reads",
            "device_writes": False,
            "mmio_width_bits": 32,
            "automatic_retries": False,
            "arbitrary_address_input": False,
        },
        "records": raw_records,
    }
    raw_bytes = json_bytes(raw)
    manifest = {
        "schema": "sdm855-a90-icb-remapper-readonly-manifest-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "mode": mode,
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "device_writes": False,
        "register_read_count": len(public_records),
        "records": public_records,
        "runtime_version_payload_sha256": sha256(before.payload),
        "raw_snapshot_sha256": sha256(raw_bytes),
        "raw_snapshot_size": len(raw_bytes),
        "claim_boundary": (
            "A successful capture proves post-boot EL1 /dev/mem readability and "
            "boot values only; it does not prove writability, aliasing, or final "
            "DRAM channel/bank/row semantics"
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
        "--full",
        action="store_true",
        help="read all 23 proved layout-1 words per instance instead of offset 0",
    )
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
