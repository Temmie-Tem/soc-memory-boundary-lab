#!/usr/bin/env python3
"""Capture fixed `/proc/last_kmsg` from the bound A90 native runtime.

The tool sends only `version`, `cat /proc/last_kmsg`, and `selftest status`
through A90P1 after a best-effort raw `hide`. The binary payload remains
private; the public manifest contains hashes, sizes, and bounded marker counts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib
import re
import sys
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import Command, exchange, json_bytes, write_new
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import Command, exchange, json_bytes, write_new


A90CTL_PATH = Path(
    "/home/temmie/dev/android-native-init-lab/workspace/public/src/scripts/"
    "revalidation/a90ctl.py"
)
A90CTL_SHA256 = "4d72b87b42ef49c5997ddcd24d0c6bb4fe94766c2c7fddaa21b07ff218009f8c"
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
MARKERS = (
    b"Non Secure Watchdog Bark",
    b"watchdog",
    b"Watchdog",
    b"A90R",
    b"last pet",
    b"Last pet",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_a90ctl():
    data = A90CTL_PATH.read_bytes()
    if sha256(data) != A90CTL_SHA256:
        raise RuntimeError("a90ctl SHA-256 mismatch")
    parent = str(A90CTL_PATH.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    return importlib.import_module("a90ctl")


def marker_summary(payload: bytes) -> dict[str, object]:
    counts = {
        marker.decode("ascii"): payload.count(marker)
        for marker in MARKERS
    }
    return {
        "counts": counts,
        "non_secure_watchdog_bark_present": counts["Non Secure Watchdog Bark"] > 0,
        "a90r_result_present": counts["A90R"] > 0,
    }


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if SAFE_ID_RE.fullmatch(args.experiment_id) is None:
        raise ValueError("experiment ID has invalid characters")
    ctl = load_a90ctl()
    try:
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
    except Exception:
        pass

    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    before = exchange(
        args.host, args.port, Command("version_before", ("version",)), args.timeout
    )
    retained = exchange(
        args.host,
        args.port,
        Command("last_kmsg", ("cat", "/proc/last_kmsg")),
        args.timeout,
    )
    after = exchange(
        args.host,
        args.port,
        Command("selftest_after", ("selftest", "status")),
        args.timeout,
    )
    completed = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    root = args.output_root.resolve()
    raw_path = root / "evidence/private" / f"{args.experiment_id}.last_kmsg.bin"
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    write_new(raw_path, retained.payload, 0o600)
    summary = marker_summary(retained.payload)
    manifest = {
        "schema": "sdm855-a90-last-kmsg-capture-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "device_write": False,
        "commands": ["version", "cat /proc/last_kmsg", "selftest status"],
        "version_status": before.end["status"],
        "selftest_status": after.end["status"],
        "retained_size": len(retained.payload),
        "retained_sha256": sha256(retained.payload),
        "markers": summary,
        "private_record": {
            "filename": raw_path.name,
            "size": len(retained.payload),
            "sha256": sha256(retained.payload),
            "git_ignored": True,
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return raw_path, manifest_path


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=54321)
    parser.add_argument("--timeout", type=float, default=45.0)
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
