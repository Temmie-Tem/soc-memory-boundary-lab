#!/usr/bin/env python3
"""Collect only ``SHRM_MEM.BIN`` from an A90 Sahara memory-debug session.

The collector pins the official linux-msm/qdl v2.8 release binary retained in
private evidence and fixes the qdl segment filter to ``SHRM_MEM.BIN``.  It
refuses to start when any Qualcomm USB device is already visible, so the first
05c6 device appearing after launch is the controlled A90 transition.  QDL
requests no other dump segment and sends the protocol reset after collection.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools.shrm_dump_decode import DUMP_SIZE, build_manifest, decode
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new  # type: ignore
    from shrm_dump_decode import DUMP_SIZE, build_manifest, decode  # type: ignore


REPO_ROOT = Path(__file__).resolve().parents[1]
QDL_DIR = (
    REPO_ROOT
    / "evidence/private/host-tools/qdl-v2.8/extracted/qdl-binary-ubuntu-24-x64"
)
QDL_BINARY = QDL_DIR / "qdl"
QDL_LOADER = Path("/lib64/ld-linux-x86-64.so.2")
QDL_SHA256 = "8066d34f2aefdfa64afa43a44c630a5e43a6b9da991d2b0b4dae5acaf0da26e5"
QDL_ZIP_SHA256 = "80e2fb22c093ce6641ee0102dd45f5851f4fc65803d0e8d359c4080699e5af6c"
QDL_TAG = "v2.8"
QDL_TAG_COMMIT = "ced92634a8e4f0681cd1137c5bba079b23479c44"
QDL_RELEASE_URL = "https://github.com/linux-msm/qdl/releases/tag/v2.8"
FILTER = "SHRM_MEM.BIN"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_qdl() -> dict[str, object]:
    data = QDL_BINARY.read_bytes()
    digest = sha256(data)
    if digest != QDL_SHA256:
        raise ValueError(f"qdl SHA-256 {digest} != exact release pin")
    result = subprocess.run(
        [
            str(QDL_LOADER),
            "--library-path",
            str(QDL_DIR),
            str(QDL_BINARY),
            "--version",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = result.stdout.decode("utf-8", errors="strict").strip()
    if result.returncode != 0 or output != "qdl version v2.8":
        raise ValueError(f"qdl version self-check failed: rc={result.returncode} {output!r}")
    return {
        "tag": QDL_TAG,
        "tag_commit": QDL_TAG_COMMIT,
        "release_url": QDL_RELEASE_URL,
        "binary_sha256": digest,
        "release_zip_sha256": QDL_ZIP_SHA256,
        "version_output": output,
    }


def qdl_command(output_dir: Path) -> list[str]:
    return [
        str(QDL_LOADER),
        "--library-path",
        str(QDL_DIR),
        str(QDL_BINARY),
        "ramdump",
        "--debug",
        "--backend=usb",
        "-o",
        str(output_dir),
        FILTER,
    ]


def qualcomm_usb_lines() -> list[str]:
    result = subprocess.run(
        ["/usr/bin/lsusb", "-d", "05c6:"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"lsusb Qualcomm preflight failed: {result.stderr!r}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def collect(args: argparse.Namespace) -> tuple[Path, Path]:
    if not args.execute:
        raise ValueError("Sahara collection/reset requires explicit --execute")
    if not args.experiment_id or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789._-"
        for character in args.experiment_id
    ):
        raise ValueError("invalid experiment ID")
    qdl = validate_qdl()
    visible_before = qualcomm_usb_lines()
    if visible_before:
        raise ValueError(f"Qualcomm USB device already visible before trigger: {visible_before}")

    root = args.output_root.resolve()
    private_dir = root / "evidence/private" / args.experiment_id
    dump_dir = private_dir / "dump"
    log_path = private_dir / "qdl.log"
    metadata_path = private_dir / "capture-metadata.json"
    manifest_path = root / "evidence/manifests" / f"{args.experiment_id}.manifest.json"
    if private_dir.exists() or manifest_path.exists():
        raise FileExistsError("collector evidence already exists")
    private_dir.mkdir(parents=True, mode=0o700)
    dump_dir.mkdir(mode=0o700)
    os.chmod(private_dir, 0o700)
    os.chmod(dump_dir, 0o700)

    command = qdl_command(dump_dir)
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    print("QDL_READY: waiting for first Qualcomm Sahara device; filter=SHRM_MEM.BIN", flush=True)
    with log_path.open("wb") as log_stream:
        os.chmod(log_path, 0o600)
        process = subprocess.Popen(command, stdout=log_stream, stderr=subprocess.STDOUT)
        try:
            returncode = process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5.0)
            returncode = process.returncode
            timed_out = True
        else:
            timed_out = False
        log_stream.flush()
        os.fsync(log_stream.fileno())

    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    log_data = log_path.read_bytes()
    dump_path = dump_dir / FILTER
    dump_files = sorted(path.name for path in dump_dir.iterdir() if path.is_file())
    captured = dump_path.is_file()
    dump_data = dump_path.read_bytes() if captured else None
    exact_size = dump_data is not None and len(dump_data) == DUMP_SIZE
    decoded_manifest = None
    decode_error = None
    if exact_size:
        try:
            plans = decode(dump_data)
            decoded_manifest = build_manifest(plans, dump_path, dump_data)
        except Exception as exc:
            decode_error = f"{type(exc).__name__}: {exc}"

    if returncode == 0 and captured and exact_size and decoded_manifest is not None:
        classification = "SHRM_DUMP_CAPTURED_AND_STRUCTURALLY_DECODED"
    elif captured:
        classification = "SHRM_DUMP_CAPTURED_BUT_DECODE_INCOMPLETE"
    else:
        classification = "NO_SHRM_DUMP_CAPTURED"

    private = {
        "schema": "sdm855-a90-shrm-sahara-capture-private-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "qdl": qdl,
        "command": command,
        "visible_qualcomm_usb_before": visible_before,
        "returncode": returncode,
        "timed_out": timed_out,
        "qdl_log_sha256": sha256(log_data),
        "qdl_log_size": len(log_data),
        "dump_files": dump_files,
        "dump": {
            "filename": FILTER if captured else None,
            "size": len(dump_data) if dump_data is not None else None,
            "sha256": sha256(dump_data) if dump_data is not None else None,
        },
        "decode_error": decode_error,
        "decoded_manifest": decoded_manifest,
        "classification": classification,
    }
    write_new(metadata_path, json_bytes(private), 0o600)
    manifest = {
        "schema": "sdm855-a90-shrm-sahara-capture-public-v1",
        "experiment_id": args.experiment_id,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "collector": qdl,
        "filter": FILTER,
        "filter_count": 1,
        "qdl_returncode": returncode,
        "timed_out": timed_out,
        "qdl_log_sha256": sha256(log_data),
        "dump_files": dump_files,
        "dump": private["dump"],
        "decode": decoded_manifest,
        "classification": classification,
        "protocol_reset_expected_after_collection": True,
        "raw_dump_git_ignored": True,
        "claims": {
            "PROVED": [
                "The host collector used the exact pinned qdl v2.8 binary with one fixed SHRM_MEM.BIN segment filter."
            ],
            "UNKNOWN": []
            if decoded_manifest is not None
            else [
                "Whether the exact A90 exposes a compatible Qualcomm Sahara memory-debug USB interface and returns SHRM_MEM.BIN."
            ],
        },
    }
    write_new(manifest_path, json_bytes(manifest), 0o644)
    print(f"QDL_DONE: {classification}; rc={returncode}; files={dump_files}", flush=True)
    return metadata_path, manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--output-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--self-check", action="store_true", help="validate pinned qdl without device contact"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_check:
        print(json.dumps(validate_qdl(), indent=2, sort_keys=True))
        return 0
    metadata, manifest = collect(args)
    print(f"private metadata: {metadata}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
