#!/usr/bin/env python3
"""Capture a fixed, read-only A90 native runtime health receipt."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import re
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from tools.a90_last_kmsg_capture import load_a90ctl, sha256
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new
    from a90_last_kmsg_capture import load_a90ctl, sha256


SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
VERSION_RE = re.compile(
    rb"version: (?P<version>[^\r\n ]+) build=(?P<build>[^\r\n ]+)"
)
SELFTEST_RE = re.compile(
    rb"selftest: pass=(?P<passed>[0-9]+) warn=(?P<warn>[0-9]+) "
    rb"fail=(?P<fail>[0-9]+) duration=(?P<duration>[0-9]+)ms entries=(?P<entries>[0-9]+)"
)


def parse_version(payload: bytes) -> dict[str, str]:
    match = VERSION_RE.search(payload)
    if match is None:
        raise ValueError("version payload lacks exact version/build line")
    return {key: value.decode("ascii") for key, value in match.groupdict().items()}


def parse_selftest(payload: bytes) -> dict[str, int]:
    match = SELFTEST_RE.search(payload)
    if match is None:
        raise ValueError("selftest payload lacks exact summary")
    result = {key: int(value) for key, value in match.groupdict().items()}
    if result["fail"] != 0:
        raise ValueError("runtime selftest reports failures")
    return result


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    ctl = load_a90ctl()
    ctl.bridge_exchange(
        args.host,
        args.port,
        "hide",
        min(args.timeout, 8.0),
        markers=(b"[busy]", b"[done]", b"[err]"),
        input_mode="slow",
        require_prompt_after_end=False,
        post_marker_drain_sec=0.0,
    )
    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    commands = (
        Command("version", ("version",)),
        Command("selftest", ("selftest", "status")),
        Command(
            "battery_capacity",
            ("cat", "/sys/class/power_supply/battery/capacity"),
        ),
    )
    frames = [exchange(args.host, args.port, command, args.timeout) for command in commands]
    version = parse_version(frames[0].payload)
    selftest = parse_selftest(frames[1].payload)
    battery_text = frames[2].payload.decode("ascii", errors="strict").strip()
    if not battery_text.isdigit() or not 0 <= int(battery_text) <= 100:
        raise ValueError("battery capacity is not a bounded decimal percentage")
    completed = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    raw = {
        "schema": "sdm855-a90-runtime-health-private-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "records": [
            {
                "evidence_id": command.evidence_id,
                "argv": list(command.argv),
                "begin": frame.begin,
                "end": frame.end,
                "payload_base64": base64.b64encode(frame.payload).decode("ascii"),
                "payload_sha256": sha256(frame.payload),
                "transcript_sha256": sha256(frame.transcript),
            }
            for command, frame in zip(commands, frames)
        ],
        "version": version,
        "selftest": selftest,
        "battery_capacity_percent": int(battery_text),
    }
    raw_bytes = json_bytes(raw)
    root = args.output_root.resolve()
    raw_path = root / "evidence/private" / f"{args.experiment_id}.json"
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    write_new(raw_path, raw_bytes, 0o600)
    manifest = {
        "schema": "sdm855-a90-runtime-health-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "device_write": False,
        "version": version,
        "selftest": selftest,
        "battery_capacity_percent": int(battery_text),
        "all_status_ok": all(frame.end["status"] == "ok" for frame in frames),
        "raw_snapshot_sha256": sha256(raw_bytes),
        "raw_snapshot_size": len(raw_bytes),
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return raw_path, manifest_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output-root", type=Path, default=Path("."))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    raw, manifest = collect(args)
    print(raw)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
