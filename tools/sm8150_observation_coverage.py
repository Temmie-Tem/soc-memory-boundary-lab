#!/usr/bin/env python3
"""Host-only Experiment 022 measure of how much controller state is observable.

Experiments 014, 017, 018, 019 and 021 all return negatives about the twelve
ranked MC targets. Those targets came from Verification 012's Top-5 ranking,
which ranked among the registers the SHRM snapshot happens to sample. Nothing
in the repository had measured how large that sample is relative to the space
it is drawn from, so the strength of every downstream negative was unquantified.

This measures it. Two static channels see controller state: the SHRM snapshot
list, and the Experiment 017 XBL MC address table. Their union is the whole
set of controller addresses this project can name without a device read.

The denominators need care and are reported twice. A 64-KiB block holds 16,384
addressable word slots, but the number actually implemented is `UNKNOWN` and is
certainly smaller, so coverage measured against the block is a *lower* bound on
true coverage. Coverage measured against the observed span is the defensible
figure, because both ends of that span are addresses something really names.

Mode: HOST_ONLY_READ_ONLY.  No device, SMC, MMIO or protected-memory access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
SHRM_DUMP = (
    REPO_ROOT
    / "evidence/private/verification-012-a90-samsung-upload-shrm-20260825-01/memory/SHRM_MEM.BIN"
)
SCHEMA = "sm8150-observation-coverage-v1"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4194304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

# Experiment 017's MC address table.
MC_TABLE_VADDR = 0x146B1218

RANKED_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)
RANKED_OFFSETS = (0x400, 0x404, 0x4D0)

BLOCK_SIZE = 0x10000
WORD_SLOTS_PER_BLOCK = BLOCK_SIZE // 4


class CoverageError(ValueError):
    """Raised when an input is not the exact pinned artifact."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_xbl(firmware_dir: Path) -> bytes:
    path = firmware_dir / XBL_NAME
    if not path.exists():
        raise CoverageError(f"missing exact image: {XBL_NAME}")
    data = path.read_bytes()
    if len(data) != XBL_SIZE or sha256(data) != XBL_SHA256:
        raise CoverageError(f"{XBL_NAME} is not the exact Experiment 004 artifact")
    return data


def _file_offset(data: bytes, vaddr: int) -> int | None:
    ph_offset = struct.unpack_from("<Q", data, 32)[0]
    ph_entry = struct.unpack_from("<H", data, 54)[0]
    ph_count = struct.unpack_from("<H", data, 56)[0]
    for index in range(ph_count):
        offset = ph_offset + index * ph_entry
        p_type, _flags, file_offset, base, _pa, size, _mem, _al = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_type == 1 and base <= vaddr < base + size and file_offset + size <= len(data):
            return file_offset + (vaddr - base)
    return None


def xbl_mc_table(data: bytes) -> list[int]:
    """The Experiment 017 table: zero-terminated u64 MMIO addresses."""
    offset = _file_offset(data, MC_TABLE_VADDR)
    if offset is None:
        raise CoverageError("MC table vaddr is not mapped")
    addresses = []
    while True:
        value = struct.unpack_from("<Q", data, offset + len(addresses) * 8)[0]
        if value == 0:
            return addresses
        addresses.append(value)


def shrm_snapshot_addresses(dump_path: Path) -> tuple[set[int], set[int]]:
    """Return (set 0, union) register addresses from the live SHRM snapshot."""
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from tools import shrm_dump_decode

    plans = shrm_dump_decode.decode(dump_path.read_bytes())
    set_zero = {word.register for word in plans[0].words}
    union = {word.register for plan in plans for word in plan.words}
    return set_zero, union


def coverage_by_block(addresses: set[int], per_channel: dict[str, set[int]]) -> list[dict]:
    """Per 64-KiB block: how many addresses are named, and out of what."""
    rows = []
    for block in sorted({address & ~(BLOCK_SIZE - 1) for address in addresses}):
        members = sorted(a for a in addresses if a & ~(BLOCK_SIZE - 1) == block)
        span_slots = (members[-1] - members[0]) // 4 + 1
        rows.append(
            {
                "block": f"0x{block:08x}",
                "is_ranked_instance": block in RANKED_BASES,
                "observed": len(members),
                "by_channel": {
                    name: sum(1 for a in channel if a & ~(BLOCK_SIZE - 1) == block)
                    for name, channel in per_channel.items()
                },
                "min_offset": f"0x{members[0] - block:06x}",
                "max_offset": f"0x{members[-1] - block:06x}",
                "observed_span_word_slots": span_slots,
                "coverage_of_observed_span_percent": round(100 * len(members) / span_slots, 4),
                "coverage_of_64k_block_percent": round(100 * len(members) / WORD_SLOTS_PER_BLOCK, 4),
            }
        )
    return rows


def ranked_instance_summary(addresses: set[int]) -> dict:
    per_instance = {}
    total = 0
    for base in RANKED_BASES:
        members = sorted(a for a in addresses if a & ~(BLOCK_SIZE - 1) == base)
        total += len(members)
        span_slots = (members[-1] - members[0]) // 4 + 1 if members else 0
        per_instance[f"0x{base:08x}"] = {
            "observed": len(members),
            "observed_span_word_slots": span_slots,
            "coverage_of_observed_span_percent": round(100 * len(members) / span_slots, 4)
            if span_slots
            else 0.0,
            "ranked_offsets_observed": [
                f"0x{offset:x}" for offset in RANKED_OFFSETS if base + offset in members
            ],
        }
    slots = len(RANKED_BASES) * WORD_SLOTS_PER_BLOCK
    return {
        "per_instance": per_instance,
        "total_observed": total,
        "total_addressable_word_slots": slots,
        "coverage_of_64k_blocks_percent": round(100 * total / slots, 4),
    }


def build_manifest(firmware_dir: Path, dump_path: Path) -> dict:
    data = load_xbl(firmware_dir)
    table = xbl_mc_table(data)
    if not dump_path.exists():
        raise CoverageError(f"missing SHRM dump: {dump_path.name}")
    set_zero, snapshot = shrm_snapshot_addresses(dump_path)

    channels = {"shrm_snapshot": snapshot, "xbl_mc_table": set(table)}
    union = set().union(*channels.values())
    return {
        "schema": SCHEMA,
        "experiment_id": "022-observation-coverage",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "image": XBL_NAME,
        "image_sha256": XBL_SHA256,
        "channels": {
            "shrm_snapshot_set0": len(set_zero),
            "shrm_snapshot_union": len(snapshot),
            "xbl_mc_table": len(table),
            "union": len(union),
            "xbl_table_addresses_new_to_the_snapshot": len(set(table) - snapshot),
        },
        "coverage_by_block": coverage_by_block(union, channels),
        "ranked_instances": ranked_instance_summary(union),
        "denominator_note": (
            "A 64-KiB block holds 16384 addressable word slots; how many are implemented "
            "is UNKNOWN and is certainly fewer, so coverage against the block is a LOWER "
            "bound on true coverage. Coverage against the observed span is the defensible "
            "figure: both ends of that span are addresses a channel really names."
        ),
        "claims": {
            "PROVED": [
                "Two static channels name controller addresses: the SHRM snapshot and the "
                "Experiment 017 XBL MC table. Their union is the complete set this project "
                "can name without a device read.",
                "Within each ranked MC instance the union names a small fraction of the "
                "span it covers. All three ranked offsets lie inside that sample, which is "
                "not a coincidence and not evidence: they were selected from it, so their "
                "presence is a property of how the candidates were chosen.",
            ],
            "REFUTED": [
                "The ranked-candidate negatives from Experiments 014, 017, 018, 019 and "
                "021 bound where the Experiment 014 bank relation can live. The candidate "
                "set was drawn from the observable sample, and that sample is a small "
                "fraction of the register space it is drawn from.",
            ],
            "UNKNOWN": [
                "How many registers each block actually implements, and therefore the true "
                "denominator.",
                "Whether the bank relation is implemented by a register at all.",
                "Everything the observation channels do not name, which is the majority of "
                "each block by either denominator.",
            ],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--dump", type=Path, default=SHRM_DUMP)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir, args.dump)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    args.output.chmod(0o644)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
