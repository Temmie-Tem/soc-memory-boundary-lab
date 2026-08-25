#!/usr/bin/env python3
"""Dispatch one exact A90 SysRq crash after a collector is already waiting."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import os
import re
import socket
import time
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from tools.a90_param_capture import parse_cmdline, validate_runtime
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new  # type: ignore
    from a90_param_capture import parse_cmdline, validate_runtime  # type: ignore


SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
BEGIN_RE = re.compile(rb"A90P1 BEGIN [^\r\n]*\bcmd=writefile\b")
WIRE = b"\ncmdv1 writefile /proc/sysrq-trigger c\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    data = json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def validate_transcript(transcript: bytes) -> dict[str, object]:
    accepted = BEGIN_RE.search(transcript) is not None
    if not accepted:
        raise ValueError("crash transcript lacks exact A90P1 writefile BEGIN")
    return {
        "a90p1_writefile_begin_observed": True,
        "transcript_sha256": sha256(transcript),
        "transcript_size": len(transcript),
    }


def dispatch_once(host: str, port: int, timeout: float) -> tuple[bytes, bool]:
    data = bytearray()
    disconnected = False
    with socket.create_connection((host, port), timeout=min(timeout, 3.0)) as sock:
        sock.settimeout(0.2)
        sock.sendall(WIRE)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                disconnected = True
                break
            if not chunk:
                disconnected = True
                break
            data.extend(chunk)
            if BEGIN_RE.search(data):
                deadline = min(deadline, time.monotonic() + 8.0)
    return bytes(data), disconnected


def _read(host: str, port: int, evidence_id: str, argv: tuple[str, ...], timeout: float) -> bytes:
    return exchange(host, port, Command(evidence_id, argv), timeout).payload


def preflight(host: str, port: int, timeout: float) -> dict[str, object]:
    version = _read(host, port, "version", ("version",), timeout)
    cmdline_raw = _read(host, port, "cmdline", ("cat", "/proc/cmdline"), timeout)
    cmdline = parse_cmdline(cmdline_raw)
    validate_runtime(version, cmdline)
    expected = {
        "androidboot.debug_level": "0x494d",
        "androidboot.force_upload": "0x0",
        "sec_debug.dump_sink": "0x0",
    }
    for key, value in expected.items():
        if cmdline.get(key) != value:
            raise ValueError(f"crash precondition {key}={cmdline.get(key)!r}, expected {value!r}")
    scalars = {}
    for name, path in (
        ("download_mode", "/sys/module/msm_poweroff/parameters/download_mode"),
        ("panic", "/sys/module/kernel/parameters/panic"),
        ("panic_on_warn", "/sys/module/kernel/parameters/panic_on_warn"),
        ("sysrq", "/proc/sys/kernel/sysrq"),
    ):
        scalars[name] = _read(host, port, name, ("cat", path), timeout).decode(
            "ascii", errors="strict"
        ).strip()
    if scalars != {
        "download_mode": "1",
        "panic": "-1",
        "panic_on_warn": "0",
        "sysrq": "1",
    }:
        raise ValueError(f"crash scalar preconditions changed: {scalars}")
    stat = _read(host, port, "sysrq_stat", ("stat", "/proc/sysrq-trigger"), timeout)
    if b"mode=0200" not in stat:
        raise ValueError(f"sysrq trigger is not the expected write-only node: {stat!r}")
    return {"cmdline": cmdline, "scalars": scalars, "sysrq_stat": stat.decode("ascii")}


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if not args.execute:
        raise ValueError("crash requires explicit --execute")
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("invalid experiment ID")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("crash tool only accepts a loopback bridge")
    root = args.output_root.resolve()
    journal_path = root / "evidence/private" / f"{args.experiment_id}.journal.json"
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    if journal_path.exists() or manifest_path.exists():
        raise FileExistsError("crash evidence exists; effect replay is forbidden")
    state = preflight(args.host, args.port, args.command_timeout)
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    journal: dict[str, object] = {
        "schema": "sdm855-a90-sysrq-crash-journal-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "status": "INTENT_DURABLE_PRE_EFFECT",
        "effect": "writefile /proc/sysrq-trigger c",
        "effect_dispatched": False,
        "effect_replayed": False,
        "preflight": state,
    }
    _atomic_json(journal_path, journal)
    journal["effect_dispatched"] = True
    journal["status"] = "EFFECT_DISPATCH_STARTED"
    _atomic_json(journal_path, journal)
    try:
        transcript, disconnected = dispatch_once(args.host, args.port, args.dispatch_timeout)
        receipt = validate_transcript(transcript)
        receipt["socket_disconnect_observed"] = disconnected
        receipt["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
        journal["dispatch_receipt"] = receipt
        journal["completed_utc"] = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat()
        journal["status"] = "CRASH_DISPATCHED_NO_REPLAY"
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        journal["status"] = "EFFECT_DISPATCHED_OUTCOME_AMBIGUOUS_NO_REPLAY"
        journal["error"] = f"{type(exc).__name__}: {exc}"
        _atomic_json(journal_path, journal)
        raise

    manifest = {
        "schema": "sdm855-a90-sysrq-crash-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": journal["completed_utc"],
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "classification": journal["status"],
        "effect": journal["effect"],
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "preflight": {
            "debug_level": state["cmdline"]["androidboot.debug_level"],
            "force_upload": state["cmdline"]["androidboot.force_upload"],
            "dump_sink": state["cmdline"]["sec_debug.dump_sink"],
            **state["scalars"],
        },
        "dispatch_receipt": {
            key: value
            for key, value in journal["dispatch_receipt"].items()
            if key != "transcript_base64"
        },
        "claims": {
            "PROVED": [
                "One exact SysRq crash write was accepted by A90P1; it was not retried."
            ],
            "UNKNOWN": [
                "Dump entry and SHRM export are classified only by the separate host collector result."
            ],
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return journal_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--command-timeout", type=float, default=15.0)
    parser.add_argument("--dispatch-timeout", type=float, default=15.0)
    parser.add_argument("--output-root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    journal, manifest = collect(args)
    print(f"journal: {journal}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
