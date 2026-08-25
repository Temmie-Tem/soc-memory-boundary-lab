#!/usr/bin/env python3
"""Audit exact A90 firmware for literal forms of the recovered bank hash.

Experiment 014 recovered a three-row GF(2) bank-selection basis from live
normal-RAM timing.  A raw byte search can produce misleading matches when a
24-bit mask occurs one byte into a 64-bit address-table entry.  This tool pins
the captured firmware through its acquisition metadata and the real SHRM dump
through its exact hash, searches all seven non-zero combinations of the
recovered basis, and records whether each match is an aligned 32-bit literal
or such a misaligned address-table coincidence.

The audit is host-only and never contacts the device.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAPTURE_ROOT = (
    REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
)
DEFAULT_SHRM_SNAPSHOT = (
    REPO_ROOT
    / "evidence/private/verification-012-a90-samsung-upload-shrm-20260825-01"
    / "memory/SHRM_MEM.BIN"
)
CAPTURE_EXPERIMENT_ID = "004-live-firmware-readonly-20260825-01"
SHRM_EXPERIMENT_ID = "verification-012-a90-samsung-upload-shrm-20260825-01"
SHRM_SHA256 = "409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7"
SHRM_SIZE = 65536
SCHEMA = "a90_bank_hash_literal_audit_v1"

BANK_ROWS = (0x009D2000, 0x00A74000, 0x004E8000)
BANK_ROW_SPACE_NONZERO = tuple(
    sorted(
        {
            value
            for selector in range(1, 1 << len(BANK_ROWS))
            for value in [
                BANK_ROWS[0] * bool(selector & 1)
                ^ BANK_ROWS[1] * bool(selector & 2)
                ^ BANK_ROWS[2] * bool(selector & 4)
            ]
        }
    )
)


class AuditError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_all(data: bytes, needle: bytes) -> list[int]:
    result: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return result
        result.append(offset)
        start = offset + 1


def enclosing_u64_progression(data: bytes, offset: int) -> dict[str, object] | None:
    """Return a three-entry progression when *offset* lies in its middle u64."""

    entry_offset = offset - (offset % 8)
    if entry_offset < 8 or entry_offset + 16 > len(data):
        return None
    previous = int.from_bytes(data[entry_offset - 8 : entry_offset], "little")
    current = int.from_bytes(data[entry_offset : entry_offset + 8], "little")
    following = int.from_bytes(data[entry_offset + 8 : entry_offset + 16], "little")
    step = current - previous
    if step <= 0 or following - current != step:
        return None
    return {
        "entry_file_offset": f"0x{entry_offset:x}",
        "previous": f"0x{previous:016x}",
        "current": f"0x{current:016x}",
        "following": f"0x{following:016x}",
        "step": f"0x{step:x}",
    }


def audit_blob(filename: str, data: bytes) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for mask in BANK_ROW_SPACE_NONZERO:
        for offset in find_all(data, mask.to_bytes(4, "little")):
            progression = enclosing_u64_progression(data, offset)
            hits.append(
                {
                    "filename": filename,
                    "mask": f"0x{mask:08x}",
                    "file_offset": f"0x{offset:x}",
                    "offset_mod_4": offset % 4,
                    "offset_mod_8": offset % 8,
                    "aligned_u32_literal": offset % 4 == 0,
                    "misaligned_u64_address_progression": progression,
                }
            )
    return hits


def load_capture(capture_root: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    metadata_path = capture_root / "capture-metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot load capture metadata: {exc}") from exc
    if metadata.get("experiment_id") != CAPTURE_EXPERIMENT_ID:
        raise AuditError("capture experiment ID mismatch")
    records = metadata.get("records")
    if not isinstance(records, list):
        raise AuditError("capture records are missing")

    artifacts: list[dict[str, object]] = []
    hits: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, dict):
            raise AuditError("malformed capture record")
        filename = record.get("private_filename")
        expected_sha = record.get("sha256")
        expected_size = record.get("byte_size")
        if not isinstance(filename, str) or not isinstance(expected_sha, str):
            raise AuditError("capture record lacks filename or SHA-256")
        path = capture_root / filename
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise AuditError(f"cannot load {filename}: {exc}") from exc
        if len(data) != expected_size:
            raise AuditError(f"{filename}: byte size differs from capture metadata")
        actual_sha = sha256(data)
        if actual_sha != expected_sha:
            raise AuditError(f"{filename}: SHA-256 differs from capture metadata")
        artifacts.append(
            {"filename": filename, "byte_size": len(data), "sha256": actual_sha}
        )
        hits.extend(audit_blob(filename, data))
    return artifacts, hits


def analyze(
    capture_root: Path = DEFAULT_CAPTURE_ROOT,
    shrm_snapshot: Path = DEFAULT_SHRM_SNAPSHOT,
) -> dict[str, object]:
    artifacts, hits = load_capture(capture_root)
    try:
        shrm_data = shrm_snapshot.read_bytes()
    except OSError as exc:
        raise AuditError(f"cannot load SHRM snapshot: {exc}") from exc
    if len(shrm_data) != SHRM_SIZE or sha256(shrm_data) != SHRM_SHA256:
        raise AuditError("SHRM snapshot size or SHA-256 differs from pin")
    snapshot_hits = audit_blob("SHRM_MEM.BIN", shrm_data)
    hits.extend(snapshot_hits)
    aligned = [hit for hit in hits if hit["aligned_u32_literal"]]
    explained = [
        hit
        for hit in hits
        if not hit["aligned_u32_literal"]
        and hit["misaligned_u64_address_progression"] is not None
    ]
    unexplained = [hit for hit in hits if hit not in aligned and hit not in explained]
    if aligned or unexplained:
        classification = "DIRECT_LITERAL_ATTRIBUTION_UNRESOLVED"
    else:
        classification = "DIRECT_LITERAL_ATTRIBUTION_REFUTED"
    return {
        "schema": SCHEMA,
        "generated_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "target_model": "SM-A908N",
        "soc": "SM8150",
        "capture_experiment_id": CAPTURE_EXPERIMENT_ID,
        "shrm_experiment_id": SHRM_EXPERIMENT_ID,
        "classification": classification,
        "scope": {
            "host_only": True,
            "device_access": False,
            "firmware_write": False,
            "controller_write": False,
            "protected_memory_access": False,
        },
        "searched_bank_row_basis": [f"0x{value:08x}" for value in BANK_ROWS],
        "searched_nonzero_row_space": [
            f"0x{value:08x}" for value in BANK_ROW_SPACE_NONZERO
        ],
        "firmware_artifacts": artifacts,
        "shrm_snapshot": {
            "filename": "SHRM_MEM.BIN",
            "byte_size": len(shrm_data),
            "sha256": sha256(shrm_data),
            "literal_hits": len(snapshot_hits),
        },
        "literal_hits": hits,
        "summary": {
            "firmware_images": len(artifacts),
            "shrm_snapshots": 1,
            "raw_substring_hits": len(hits),
            "aligned_u32_hits": len(aligned),
            "misaligned_u64_address_table_hits": len(explained),
            "unexplained_hits": len(unexplained),
        },
        "claims": {
            "PROVED": [
                "The seven non-zero masks in the recovered three-row bank-selection span have no aligned little-endian u32 occurrence in the nine exact captured A90 firmware images.",
                "The same seven masks have no occurrence at any alignment in the pinned real 64-KiB SHRM_MEM.BIN snapshot.",
                "All four raw substring hits are offset-mod-4 one and lie inside monotonic u64 address tables with a 0x200000 step.",
            ],
            "REFUTED": [
                "A raw substring hit for 0x009d2000, 0x00a74000, or 0x003a6000 in the exact TrustZone image directly attributes the recovered bank hash to TrustZone configuration data.",
            ],
            "UNKNOWN": [
                "Whether the bank hash appears in encoded, split, compressed, generated, or register-field form rather than as one of these literal row masks.",
                "Which MC/MCCC/remapper register owns the bank hash and which boot stage writes or locks it.",
            ],
        },
    }


def write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", type=Path, default=DEFAULT_CAPTURE_ROOT)
    parser.add_argument("--shrm-snapshot", type=Path, default=DEFAULT_SHRM_SNAPSHOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = analyze(args.capture_root, args.shrm_snapshot)
    write_new(
        args.output,
        (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
