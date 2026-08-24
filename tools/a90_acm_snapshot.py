#!/usr/bin/env python3
"""Collect an allowlisted, read-only A90 memory-topology snapshot.

The collector speaks the existing A90P1 command protocol through an already
target-pinned loopback ACM bridge. It does not invoke adb/fastboot, accept an
arbitrary device command, retry an effect, or write device state. Binary DT
properties remain bytes all the way to base64 encoding.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


BEGIN_RE = re.compile(rb"(?:^|\r?\n)A90P1 BEGIN (?P<fields>[^\r\n]+)\r?\n")
END_RE = re.compile(rb"(?:^|\r?\n)A90P1 END (?P<fields>[^\r\n]+)\r?\n")
RESULT_SUFFIX_RE = re.compile(
    rb"(?:^|\r?\n)\[(?:done|err|busy)\] [^\r\n]*$"
)
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}\Z")


@dataclass(frozen=True)
class Command:
    evidence_id: str
    argv: tuple[str, ...]
    dt_reg: bool = False

    @property
    def wire(self) -> bytes:
        # Every argument below is compile-time fixed, whitespace-free, and NUL-free.
        return ("cmdv1 " + " ".join(self.argv) + "\n").encode("ascii")


COMMANDS: tuple[Command, ...] = (
    Command("version", ("version",)),
    Command("proc_version", ("cat", "/proc/version")),
    Command("proc_cmdline", ("cat", "/proc/cmdline")),
    Command("proc_iomem", ("cat", "/proc/iomem")),
    Command("proc_meminfo", ("cat", "/proc/meminfo")),
    Command("proc_partitions", ("cat", "/proc/partitions")),
    Command("reserved_memory_listing", ("ls", "/sys/firmware/devicetree/base/reserved-memory")),
    Command(
        "dt_hyp_mem_reg",
        ("cat", "/sys/firmware/devicetree/base/reserved-memory/hyp_mem/reg"),
        True,
    ),
    Command(
        "dt_uh_heap_reg",
        ("cat", "/sys/firmware/devicetree/base/reserved-memory/uh_heap_region/reg"),
        True,
    ),
    Command(
        "dt_rkp_reg",
        ("cat", "/sys/firmware/devicetree/base/reserved-memory/rkp_region@B0200000/reg"),
        True,
    ),
    Command(
        "dt_tima_reg",
        ("cat", "/sys/firmware/devicetree/base/reserved-memory/tima_region@B0000000/reg"),
        True,
    ),
    Command(
        "dt_qseecom_reg",
        ("cat", "/sys/firmware/devicetree/base/reserved-memory/qseecom_region/reg"),
        True,
    ),
)


@dataclass(frozen=True)
class Frame:
    begin: dict[str, str]
    end: dict[str, str]
    payload: bytes
    transcript: bytes


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_fields(raw: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in raw.decode("ascii", errors="strict").split():
        if "=" not in token:
            raise ValueError(f"malformed A90P1 field token: {token!r}")
        key, value = token.split("=", 1)
        if not key or key in fields:
            raise ValueError(f"duplicate or empty A90P1 field: {key!r}")
        fields[key] = value
    return fields


def parse_last_frame(transcript: bytes, expected_command: str) -> Frame:
    begins = list(BEGIN_RE.finditer(transcript))
    ends = list(END_RE.finditer(transcript))
    if not begins or not ends:
        raise ValueError("complete A90P1 frame not found")

    end_match = ends[-1]
    begin_match = next(
        (match for match in reversed(begins) if match.end() <= end_match.start()),
        None,
    )
    if begin_match is None:
        raise ValueError("A90P1 END has no preceding BEGIN")

    begin = parse_fields(begin_match.group("fields"))
    end = parse_fields(end_match.group("fields"))
    for key in ("seq", "cmd"):
        if begin.get(key) != end.get(key):
            raise ValueError(f"A90P1 {key} differs between BEGIN and END")
    if begin.get("cmd") != expected_command:
        raise ValueError(
            f"A90P1 command mismatch: expected {expected_command!r}, got {begin.get('cmd')!r}"
        )
    if "rc" not in end or "status" not in end:
        raise ValueError("A90P1 END lacks rc/status")

    body = transcript[begin_match.end() : end_match.start()]
    # cmd_cat adds one CRLF after the file. Removing the protocol's terminal
    # result line therefore also removes only that synthetic delimiter, never
    # binary data. Error frames use [err] rather than [done].
    result_match = RESULT_SUFFIX_RE.search(body)
    if result_match is None:
        raise ValueError("A90P1 body lacks terminal result line")
    payload = body[: result_match.start()]
    return Frame(begin, end, payload, transcript)


def read_until_frame(sock: socket.socket, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            continue
        if not chunk:
            break
        data.extend(chunk)
        end_at = data.rfind(b"A90P1 END ")
        if end_at >= 0 and (b"\na90:/#" in data[end_at:] or b"\ra90:/#" in data[end_at:]):
            return bytes(data)
    raise TimeoutError("timed out waiting for a complete A90P1 frame and prompt")


def exchange(
    host: str,
    port: int,
    command: Command,
    timeout: float,
    *,
    allow_error: bool = False,
) -> Frame:
    with socket.create_connection((host, port), timeout=min(timeout, 3.0)) as sock:
        sock.settimeout(0.2)
        # The leading newline only re-establishes the prompt; it has no command effect.
        sock.sendall(b"\n" + command.wire)
        transcript = read_until_frame(sock, timeout)
    frame = parse_last_frame(transcript, command.argv[0])
    if not allow_error and (
        int(frame.end["rc"], 0) != 0 or frame.end["status"] != "ok"
    ):
        raise RuntimeError(
            f"read-only command {command.evidence_id} failed: "
            f"rc={frame.end['rc']} status={frame.end['status']}"
        )
    return frame


def parse_dt_reg(data: bytes) -> dict[str, object]:
    if not data or len(data) % 4:
        raise ValueError(f"DT reg property has invalid byte length {len(data)}")
    cells = [int.from_bytes(data[offset : offset + 4], "big") for offset in range(0, len(data), 4)]
    parsed: dict[str, object] = {"cells": [f"0x{cell:08x}" for cell in cells]}
    if len(cells) == 4:
        base = (cells[0] << 32) | cells[1]
        size = (cells[2] << 32) | cells[3]
        parsed.update(
            {
                "base": f"0x{base:x}",
                "size": f"0x{size:x}",
                "end_inclusive": f"0x{base + size - 1:x}" if size else None,
            }
        )
    return parsed


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def write_new(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID must match [a-z0-9][a-z0-9._-]{0,79}")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("collector only accepts a loopback bridge")

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    records: list[dict[str, object]] = []
    manifest_records: list[dict[str, object]] = []

    for command in COMMANDS:
        frame = exchange(args.host, args.port, command, args.timeout)
        record = {
            "evidence_id": command.evidence_id,
            "argv": list(command.argv),
            "begin": frame.begin,
            "end": frame.end,
            "payload_base64": base64.b64encode(frame.payload).decode("ascii"),
            "payload_sha256": sha256(frame.payload),
            "payload_size": len(frame.payload),
            "transcript_sha256": sha256(frame.transcript),
            "transcript_size": len(frame.transcript),
        }
        records.append(record)
        public_record: dict[str, object] = {
            "evidence_id": command.evidence_id,
            "command": " ".join(command.argv),
            "rc": int(frame.end["rc"], 0),
            "status": frame.end["status"],
            "payload_sha256": record["payload_sha256"],
            "payload_size": record["payload_size"],
        }
        if command.dt_reg:
            public_record["decoded_reg"] = parse_dt_reg(frame.payload)
        manifest_records.append(public_record)

    raw = {
        "schema": "sdm855-memory-boundary-a90-readonly-snapshot-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "target": {
            "model": "SM-A908N",
            "soc": "SM8150",
            "expected_runtime": "v2321-usb-clean-identity-rodata",
            "expected_kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
            "boot_image_artifact_sha256": "ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb",
            "live_boot_image_hash_status": "UNKNOWN",
            "live_dtb_hash_status": "UNKNOWN",
        },
        "safety": {
            "transport": "target-pinned loopback ACM bridge supplied by operator",
            "device_commands": "fixed allowlist of version, cat, and ls",
            "device_writes": False,
            "automatic_retries": False,
        },
        "records": records,
    }
    raw_bytes = json_bytes(raw)
    manifest = {
        "schema": "sdm855-memory-boundary-redacted-manifest-v1",
        "experiment_id": args.experiment_id,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "started_utc": raw["started_utc"],
        "completed_utc": raw["completed_utc"],
        "raw_snapshot_sha256": sha256(raw_bytes),
        "raw_snapshot_size": len(raw_bytes),
        "records": manifest_records,
        "limitations": [
            "Artifact hashes identify host-side candidates, not bytes read back from the live boot device.",
            "DT reg decoding proves advertised ranges, not accessibility or enforcement ordering.",
        ],
    }

    root = Path(args.output_root).resolve()
    raw_path = root / "evidence" / "private" / f"{args.experiment_id}.json"
    manifest_path = root / "evidence" / "manifests" / f"{args.experiment_id}.manifest.json"
    write_new(raw_path, raw_bytes, 0o600)
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return raw_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--output-root", default=str(Path(__file__).resolve().parents[1]))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    raw_path, manifest_path = collect(args)
    print(f"private snapshot: {raw_path}")
    print(f"redacted manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
