#!/usr/bin/env python3
"""Flash one exact SHRM probe or V2321 rollback to the bound A90 boot node.

Only three named profiles exist: control, read, and rollback. The tool binds
the exact SM-A908N/r3q TWRP endpoint, verifies the current boot prefix against
the allowed predecessor set, writes once, verifies the full 60,882,944-byte
prefix, removes staging, and does not reboot.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools.a90_twrp_system_boot import (
        TARGET_DEVICE,
        TARGET_MODEL,
        TWRP_VERSION,
        parse_adb_devices,
        select_exact_recovery,
    )
    from tools import build_a90_inline_shrm_candidate as candidate
    from tools import build_a90_inline_remapper_candidate as inline
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from a90_twrp_system_boot import (
        TARGET_DEVICE,
        TARGET_MODEL,
        TWRP_VERSION,
        parse_adb_devices,
        select_exact_recovery,
    )
    import build_a90_inline_shrm_candidate as candidate
    import build_a90_inline_remapper_candidate as inline


BOOT_PREFIX_SIZE = 60_882_944
BOOT_BLOCK_ALIAS = "/dev/block/by-name/boot"
BOOT_BLOCK_RESOLVED = "/dev/block/sda24"
REMOTE_STAGING = "/tmp/sdm855-shrm-boot.img"
DD_BLOCK_SIZE = 4096
DD_BLOCK_COUNT = BOOT_PREFIX_SIZE // DD_BLOCK_SIZE

CONTROL_HASH = candidate.EXPECTED_HASHES[inline.MODE_CONTROL]["candidate"]
READ_HASH = candidate.EXPECTED_HASHES[inline.MODE_READ]["candidate"]
ROLLBACK_HASH = inline.BASE_SHA256


def profile_table(root: Path) -> dict[str, dict[str, object]]:
    private = root / "evidence/private/013-inline-shrm-snapshot-20260825-01"
    return {
        "control": {
            "path": private / candidate.output_names(inline.MODE_CONTROL)[0],
            "sha256": CONTROL_HASH,
            "allowed_predecessors": {ROLLBACK_HASH},
        },
        "read": {
            "path": private / candidate.output_names(inline.MODE_READ)[0],
            "sha256": READ_HASH,
            "allowed_predecessors": {ROLLBACK_HASH},
        },
        "rollback": {
            "path": inline.DEFAULT_BASE,
            "sha256": ROLLBACK_HASH,
            "allowed_predecessors": {CONTROL_HASH, READ_HASH},
        },
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_checked(argv: Sequence[str]) -> str:
    result = subprocess.run(
        list(argv),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed rc={result.returncode}: {argv!r}; "
            f"stderr={result.stderr.strip()!r}"
        )
    return result.stdout.replace("\r", "")


def adb_shell(adb: str, serial: str, command: str) -> str:
    return run_checked((adb, "-s", serial, "shell", command))


def parse_one_sha256(output: str) -> str:
    matches = re.findall(r"(?m)^([0-9a-f]{64})(?:\s|$)", output)
    if len(matches) != 1:
        raise RuntimeError(f"expected one SHA-256, got {len(matches)}")
    return matches[0]


def parse_one_decimal(output: str) -> int:
    values = [line.strip() for line in output.splitlines() if line.strip()]
    if len(values) != 1 or not values[0].isdigit():
        raise RuntimeError(f"expected one decimal value, got {values!r}")
    return int(values[0], 10)


def boot_prefix_sha256(adb: str, serial: str) -> str:
    command = (
        f"dd if={BOOT_BLOCK_RESOLVED} bs={DD_BLOCK_SIZE} "
        f"count={DD_BLOCK_COUNT} 2>/dev/null | sha256sum"
    )
    return parse_one_sha256(adb_shell(adb, serial, command))


def boot_prefix_size(adb: str, serial: str) -> int:
    command = (
        f"dd if={BOOT_BLOCK_RESOLVED} bs={DD_BLOCK_SIZE} "
        f"count={DD_BLOCK_COUNT} 2>/dev/null | wc -c"
    )
    return parse_one_decimal(adb_shell(adb, serial, command))


def flash(args: argparse.Namespace) -> Path:
    root = Path(__file__).resolve().parents[1]
    profiles = profile_table(root)
    profile = profiles[args.profile]
    image = Path(profile["path"]).resolve()
    expected_hash = str(profile["sha256"])
    allowed_predecessors = set(profile["allowed_predecessors"])
    if image.stat().st_size != BOOT_PREFIX_SIZE:
        raise RuntimeError("image size does not match the fixed boot prefix")
    if sha256_file(image) != expected_hash:
        raise RuntimeError("image SHA-256 mismatch")

    endpoint = select_exact_recovery(args.adb, run=run_checked)
    endpoints = parse_adb_devices(run_checked((args.adb, "devices")))
    help_text = adb_shell(args.adb, endpoint.serial, "twrp --help 2>&1")
    if "TWRP openrecoveryscript command line tool" not in help_text:
        raise RuntimeError("bound endpoint is not the expected TWRP CLI")
    if f"TWRP version {TWRP_VERSION}" not in help_text:
        raise RuntimeError("TWRP version mismatch")
    resolved = adb_shell(
        args.adb, endpoint.serial, f"readlink -f {BOOT_BLOCK_ALIAS}"
    ).strip()
    if resolved != BOOT_BLOCK_RESOLVED:
        raise RuntimeError(f"boot node resolved unexpectedly: {resolved!r}")
    before_hash = boot_prefix_sha256(args.adb, endpoint.serial)
    before_size = boot_prefix_size(args.adb, endpoint.serial)
    if before_size != BOOT_PREFIX_SIZE:
        raise RuntimeError("pre-write boot prefix size mismatch")
    if before_hash not in allowed_predecessors:
        raise RuntimeError(
            f"boot prefix predecessor {before_hash} is not allowed for {args.profile}"
        )

    started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    staging_removed = False
    write_output = ""
    try:
        run_checked((args.adb, "-s", endpoint.serial, "push", str(image), REMOTE_STAGING))
        remote_hash = parse_one_sha256(
            adb_shell(args.adb, endpoint.serial, f"sha256sum {REMOTE_STAGING}")
        )
        remote_size = parse_one_decimal(
            adb_shell(args.adb, endpoint.serial, f"wc -c < {REMOTE_STAGING}")
        )
        if remote_hash != expected_hash or remote_size != BOOT_PREFIX_SIZE:
            raise RuntimeError("remote staging verification mismatch")
        write_output = adb_shell(
            args.adb,
            endpoint.serial,
            f"dd if={REMOTE_STAGING} of={BOOT_BLOCK_RESOLVED} "
            f"bs={DD_BLOCK_SIZE} conv=fsync && sync",
        )
        after_hash = boot_prefix_sha256(args.adb, endpoint.serial)
        after_size = boot_prefix_size(args.adb, endpoint.serial)
        if after_hash != expected_hash or after_size != BOOT_PREFIX_SIZE:
            raise RuntimeError("post-write boot prefix verification mismatch")
    finally:
        adb_shell(args.adb, endpoint.serial, f"rm -f {REMOTE_STAGING}")
        absent = adb_shell(
            args.adb,
            endpoint.serial,
            f"if [ -e {REMOTE_STAGING} ]; then echo present; else echo absent; fi",
        ).strip()
        staging_removed = absent == "absent"
    if not staging_removed:
        raise RuntimeError("remote staging cleanup was not proved")

    completed = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    receipt = {
        "schema": "sdm855-a90-shrm-boot-flash-private-v1",
        "profile": args.profile,
        "started_utc": started,
        "completed_utc": completed,
        "target_model": TARGET_MODEL,
        "target_device": TARGET_DEVICE,
        "target_serial_sha256": endpoint.serial_sha256,
        "other_adb_endpoints_untouched": max(0, len(endpoints) - 1),
        "boot_alias": BOOT_BLOCK_ALIAS,
        "boot_node": BOOT_BLOCK_RESOLVED,
        "predecessor_sha256": before_hash,
        "image_sha256": expected_hash,
        "image_size": BOOT_PREFIX_SIZE,
        "remote_staging_sha256": remote_hash,
        "remote_staging_size": remote_size,
        "readback_sha256": after_hash,
        "readback_size": after_size,
        "write_count": 1,
        "write_output_tail": write_output[-512:],
        "staging_removed": staging_removed,
        "reboot_dispatched": False,
    }
    receipt_path = args.receipt.resolve()
    write_new(receipt_path, json_bytes(receipt), 0o600)
    return receipt_path


def make_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("control", "read", "rollback"), required=True)
    parser.add_argument("--adb", default="adb")
    parser.add_argument(
        "--receipt",
        type=Path,
        default=root / "evidence/private/013-shrm-boot-flash-receipt.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    path = flash(args)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
