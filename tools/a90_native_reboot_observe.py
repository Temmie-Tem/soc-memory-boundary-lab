#!/usr/bin/env python3
"""Dispatch one exact A90 native reboot and prove the next boot identity.

``reboot`` is an A90P1 ``CMD_NO_DONE`` command: success tears down USB before
an END frame.  This tool therefore journals intent before sending the command,
sends it exactly once, never treats a timeout as permission to replay, and
qualifies success only from a changed boot ID plus exact post-boot runtime and
cmdline observations.  It does not flash or write a partition.
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
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from tools.a90_param_capture import (
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
        parse_cmdline,
        validate_runtime,
    )
    from tools.a90_runtime_health import parse_selftest
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new  # type: ignore
    from a90_param_capture import (  # type: ignore
        TARGET_BOOTLOADER,
        TARGET_KERNEL,
        TARGET_MODEL,
        TARGET_RUNTIME,
        TARGET_SOC,
        parse_cmdline,
        validate_runtime,
    )
    from a90_runtime_health import parse_selftest  # type: ignore


SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
REBOOT_BEGIN_RE = re.compile(rb"A90P1 BEGIN [^\r\n]*\bcmd=reboot\b")
REBOOT_MARKER = b"reboot: syncing and restarting"
DEBUG_CMDLINE = {"low": "0x4f4c", "mid": "0x494d"}


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


def validate_reboot_transcript(transcript: bytes) -> dict[str, object]:
    begin = REBOOT_BEGIN_RE.search(transcript) is not None
    marker = REBOOT_MARKER in transcript
    if not begin or not marker:
        raise ValueError(
            f"reboot transcript lacks exact acceptance markers: begin={begin} marker={marker}"
        )
    return {
        "a90p1_begin_observed": begin,
        "reboot_marker_observed": marker,
        "transcript_sha256": sha256(transcript),
        "transcript_size": len(transcript),
    }


def dispatch_once(host: str, port: int, timeout: float) -> tuple[bytes, bool]:
    data = bytearray()
    disconnected = False
    with socket.create_connection((host, port), timeout=min(timeout, 3.0)) as sock:
        sock.settimeout(0.25)
        sock.sendall(b"\ncmdv1 reboot\n")
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
            if REBOOT_MARKER in data:
                # Give the CMD_NO_DONE path a bounded interval to tear down USB.
                deadline = min(deadline, time.monotonic() + 3.0)
    return bytes(data), disconnected


def _read(host: str, port: int, evidence_id: str, argv: tuple[str, ...], timeout: float) -> bytes:
    return exchange(host, port, Command(evidence_id, argv), timeout).payload


def _preflight(host: str, port: int, timeout: float) -> dict[str, object]:
    version = _read(host, port, "version_before", ("version",), timeout)
    cmdline_raw = _read(host, port, "cmdline_before", ("cat", "/proc/cmdline"), timeout)
    cmdline = parse_cmdline(cmdline_raw)
    validate_runtime(version, cmdline)
    boot_id = _read(
        host,
        port,
        "boot_id_before",
        ("cat", "/proc/sys/kernel/random/boot_id"),
        timeout,
    ).decode("ascii", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        raise ValueError("pre-reboot boot_id is malformed")
    return {"version": version, "cmdline": cmdline, "boot_id": boot_id}


def wait_for_new_boot(
    host: str, port: int, old_boot_id: str, timeout: float, poll_interval: float
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last_error = "no observation"
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            version = _read(host, port, "version_after", ("version",), 8.0)
            boot_id = _read(
                host,
                port,
                "boot_id_after",
                ("cat", "/proc/sys/kernel/random/boot_id"),
                8.0,
            ).decode("ascii", errors="strict").strip()
            if boot_id == old_boot_id:
                last_error = "bridge answered from the pre-reboot boot ID"
            else:
                return {"version": version, "boot_id": boot_id, "attempts": attempts}
        except Exception as exc:  # Device/bridge is expected to disappear temporarily.
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(poll_interval)
    raise TimeoutError(f"new native boot not observed: {last_error}")


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if not args.execute:
        raise ValueError("reboot requires explicit --execute")
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("invalid experiment ID")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("reboot observer only accepts a loopback bridge")
    root = args.output_root.resolve()
    journal_path = root / "evidence/private" / f"{args.experiment_id}.journal.json"
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    if journal_path.exists() or manifest_path.exists():
        raise FileExistsError("reboot evidence exists; the effect is never replayed")

    before = _preflight(args.host, args.port, args.command_timeout)
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    journal: dict[str, object] = {
        "schema": "sdm855-a90-native-reboot-journal-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "status": "INTENT_DURABLE_PRE_EFFECT",
        "effect": "cmdv1 reboot",
        "effect_dispatched": False,
        "effect_replayed": False,
        "expected_debug_after": args.expect_debug_after,
        "before": {
            "boot_id": before["boot_id"],
            "cmdline": before["cmdline"],
            "version_base64": base64.b64encode(before["version"]).decode("ascii"),
        },
    }
    _atomic_json(journal_path, journal)

    journal["effect_dispatched"] = True
    journal["status"] = "EFFECT_DISPATCH_STARTED"
    _atomic_json(journal_path, journal)
    try:
        transcript, disconnected = dispatch_once(
            args.host, args.port, args.dispatch_timeout
        )
        receipt = validate_reboot_transcript(transcript)
        receipt["socket_disconnect_observed"] = disconnected
        receipt["transcript_base64"] = base64.b64encode(transcript).decode("ascii")
        journal["dispatch_receipt"] = receipt
        journal["status"] = "EFFECT_ACCEPTED_WAITING_FOR_NEW_BOOT"
        _atomic_json(journal_path, journal)

        after = wait_for_new_boot(
            args.host,
            args.port,
            str(before["boot_id"]),
            args.boot_timeout,
            args.poll_interval,
        )
        cmdline_raw = _read(
            args.host, args.port, "cmdline_after", ("cat", "/proc/cmdline"), 12.0
        )
        cmdline = parse_cmdline(cmdline_raw)
        validate_runtime(after["version"], cmdline)
        expected_debug = DEBUG_CMDLINE[args.expect_debug_after]
        if cmdline.get("androidboot.debug_level") != expected_debug:
            raise ValueError(
                f"post-reboot debug level {cmdline.get('androidboot.debug_level')!r} "
                f"!= {expected_debug!r}"
            )
        if cmdline.get("androidboot.force_upload") != "0x0":
            raise ValueError("post-reboot force_upload is not zero")
        if cmdline.get("sec_debug.dump_sink") != "0x0":
            raise ValueError("post-reboot dump_sink is not USB default")
        dload = _read(
            args.host,
            args.port,
            "download_mode_after",
            ("cat", "/sys/module/msm_poweroff/parameters/download_mode"),
            12.0,
        ).decode("ascii", errors="strict").strip()
        if dload != "1":
            raise ValueError("post-reboot download_mode is not 1")
        selftest_payload = _read(
            args.host, args.port, "selftest_after", ("selftest", "status"), 20.0
        )
        selftest = parse_selftest(selftest_payload)
        journal["after"] = {
            "boot_id": after["boot_id"],
            "poll_attempts": after["attempts"],
            "cmdline": cmdline,
            "download_mode": dload,
            "selftest": selftest,
        }
        journal["completed_utc"] = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat()
        journal["status"] = "NEW_BOOT_PROVED"
        _atomic_json(journal_path, journal)
    except BaseException as exc:
        journal["status"] = "EFFECT_DISPATCHED_OBSERVATION_INCOMPLETE"
        journal["error"] = f"{type(exc).__name__}: {exc}"
        _atomic_json(journal_path, journal)
        raise

    manifest = {
        "schema": "sdm855-a90-native-reboot-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": journal["completed_utc"],
        "target_model": TARGET_MODEL,
        "soc": TARGET_SOC,
        "bootloader": TARGET_BOOTLOADER,
        "runtime": TARGET_RUNTIME,
        "kernel": TARGET_KERNEL,
        "classification": journal["status"],
        "effect_dispatched_count": 1,
        "effect_replayed": False,
        "cmd_no_done": True,
        "dispatch_receipt": {
            key: value
            for key, value in journal["dispatch_receipt"].items()
            if key != "transcript_base64"
        },
        "boot_id_changed": journal["before"]["boot_id"] != journal["after"]["boot_id"],
        "post_boot": {
            "debug_level": journal["after"]["cmdline"].get("androidboot.debug_level"),
            "force_upload": journal["after"]["cmdline"].get("androidboot.force_upload"),
            "dump_sink": journal["after"]["cmdline"].get("sec_debug.dump_sink"),
            "download_mode": journal["after"]["download_mode"],
            "selftest": journal["after"]["selftest"],
        },
        "claims": {
            "PROVED": [
                "The reboot command was dispatched exactly once and accepted by the exact A90P1 CMD_NO_DONE path.",
                "A different boot ID returned with the exact native runtime and requested source-backed debug-level cmdline value.",
            ]
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return journal_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--expect-debug-after", required=True, choices=tuple(DEBUG_CMDLINE))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--command-timeout", type=float, default=15.0)
    parser.add_argument("--dispatch-timeout", type=float, default=10.0)
    parser.add_argument("--boot-timeout", type=float, default=240.0)
    parser.add_argument("--poll-interval", type=float, default=2.0)
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
