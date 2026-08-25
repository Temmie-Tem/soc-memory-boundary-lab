#!/usr/bin/env python3
"""Host-only Experiment 022 measure of how much controller state is observable.

Experiments 014, 017, 018, 019 and 021 all return negatives about the twelve
ranked MC targets. Those targets came from Verification 012's Top-5 ranking,
which ranked among the registers the SHRM snapshot happens to sample. Nothing
in the repository had measured how large that sample is relative to the space
it is drawn from, so the strength of every downstream negative was unquantified.

This measures it. Two enumerated retained-evidence channels see controller
state: the retained SHRM snapshot list, and the Experiment 017 XBL MC address
table.
Their union is the exact count for those two channels only. It is not the
complete set of controller addresses the project can name without a device
read; the known address ``0x09248080`` is outside both channels.

The denominators need care and are reported twice. A 64-KiB block holds 16,384
addressable word slots, but the number actually implemented is `UNKNOWN`.
Accordingly the output calls the ratios *observed-span address density* and
*full-64-KiB word-slot density*, not implemented-register coverage. The true
implemented-register denominator and coverage remain `UNKNOWN`.

Mode: HOST_ONLY_READ_ONLY.  No device, SMC, MMIO or protected-memory access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
SHRM_DUMP = (
    REPO_ROOT
    / "evidence/private/verification-012-a90-samsung-upload-shrm-20260825-01/memory/SHRM_MEM.BIN"
)
SCHEMA = "sm8150-observation-coverage-v2"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4194304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

# Experiment 017's MC address table.
MC_TABLE_VADDR = 0x146B1218

RANKED_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)
RANKED_OFFSETS = (0x400, 0x404, 0x4D0)

BLOCK_SIZE = 0x10000
WORD_SLOTS_PER_BLOCK = BLOCK_SIZE // 4

SHRM_DUMP_NAME = "SHRM_MEM.BIN"
SHRM_DUMP_SIZE = 65536
SHRM_DUMP_SHA256 = "409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7"
KNOWN_COUNTEREXAMPLE_ADDRESS = 0x09248080
COUNTEREXAMPLE_SOURCE_MANIFEST = "006-xbl-memory-pipeline-inventory.json"
COUNTEREXAMPLE_SOURCE_FIELD = "ddr_remapper/icb_property/records/0/register_bases/0/address"
SHRM_DECODER_PATH = REPO_ROOT / "tools/shrm_dump_decode.py"
SHRM_DECODER_NAME = "tools/shrm_dump_decode.py"
SHRM_DECODER_SHA256 = "1cf33c9292890c2479c20c8f9470c05058348046a49dc2280d061a64e224b5a7"

MANIFEST_DIR = REPO_ROOT / "evidence/manifests"
DEPENDENCY_MANIFESTS = {
    "004-live-firmware-readonly-20260825-01.manifest.json":
        "1ed4b8b14b2e0ccf2d4ae084ea413e0395d9dc488dd5d2bb1dd872fbe20d9247",
    "017-xbl-mc-snapshot-xref-20260825-01.manifest.json":
        "b1db21235374c64de797c1a123c64ddb23c43fca9100bbd51cf7b4897ea5c61b",
    "006-xbl-memory-pipeline-inventory.json":
        "39469ac59ef0e3a2b9858b7435a4433def58d57407a4066da3854cfdd24409a5",
    "verification-012-a90-samsung-upload-shrm-20260825-01.manifest.json":
        "ab1ce8168fe52f358f9c670e1b734125ff078628fa0667568d7cdea115d6021b",
}


class CoverageError(ValueError):
    """Raised when an input is not the exact pinned artifact."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dependency_manifest_hashes(manifest_dir: Path = MANIFEST_DIR) -> dict[str, str]:
    """Validate and return every public manifest hash this experiment uses."""

    result = {}
    for name, expected in DEPENDENCY_MANIFESTS.items():
        path = manifest_dir / name
        if not path.is_file():
            raise CoverageError(f"missing dependency manifest: {name}")
        actual = sha256(path.read_bytes())
        if actual != expected:
            raise CoverageError(f"dependency manifest hash mismatch for {name}: {actual}")
        result[name] = actual
    return result


def dependency_file_hashes(decoder_path: Path = SHRM_DECODER_PATH) -> dict[str, str]:
    """Validate the imported decoder whose interpretation defines SHRM sets."""

    if not decoder_path.is_file():
        raise CoverageError(f"missing dependency file: {SHRM_DECODER_NAME}")
    actual = sha256(decoder_path.read_bytes())
    if actual != SHRM_DECODER_SHA256:
        raise CoverageError(f"dependency file hash mismatch for {SHRM_DECODER_NAME}: {actual}")
    return {SHRM_DECODER_NAME: actual}


def _manifest_field(document: object, path: tuple[str, ...]) -> object:
    current = document
    for component in path:
        if isinstance(current, dict):
            if component not in current:
                raise CoverageError(
                    f"counterexample provenance field is missing: {'/'.join(path)}"
                )
            current = current[component]
        elif isinstance(current, list):
            try:
                index = int(component)
                current = current[index]
            except (ValueError, IndexError):
                raise CoverageError(
                    f"counterexample provenance field is missing: {'/'.join(path)}"
                ) from None
        else:
            raise CoverageError(
                f"counterexample provenance field is missing: {'/'.join(path)}"
            )
    return current


def counterexample_provenance(manifest_dir: Path = MANIFEST_DIR) -> dict[str, str]:
    """Pin the source manifest and verify it really records the counterexample."""

    path = manifest_dir / COUNTEREXAMPLE_SOURCE_MANIFEST
    if not path.is_file():
        raise CoverageError(f"missing counterexample source manifest: {COUNTEREXAMPLE_SOURCE_MANIFEST}")
    actual = sha256(path.read_bytes())
    expected = DEPENDENCY_MANIFESTS[COUNTEREXAMPLE_SOURCE_MANIFEST]
    if actual != expected:
        raise CoverageError(
            f"counterexample source manifest hash mismatch: {actual}"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageError("counterexample source manifest is not valid JSON") from exc
    field_path = tuple(COUNTEREXAMPLE_SOURCE_FIELD.split("/"))
    value = _manifest_field(document, field_path)
    expected_value = f"0x{KNOWN_COUNTEREXAMPLE_ADDRESS:08x}"
    if not isinstance(value, str) or value.lower() != expected_value:
        raise CoverageError(
            "counterexample source manifest does not contain the pinned address "
            f"at {COUNTEREXAMPLE_SOURCE_FIELD}"
        )
    return {
        "manifest": COUNTEREXAMPLE_SOURCE_MANIFEST,
        "sha256": actual,
        "field": COUNTEREXAMPLE_SOURCE_FIELD,
        "value": value,
    }


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
    """Return (set 0, union) from the exact retained SHRM_MEM.BIN.

    The raw file is an input pin, not merely an optional fixture. A size or
    hash mismatch is rejected before the decoder gets to interpret it.
    """
    import sys

    dependency_file_hashes()
    raw = dump_path.read_bytes()
    if len(raw) != SHRM_DUMP_SIZE:
        raise CoverageError(
            f"{SHRM_DUMP_NAME} size mismatch: {len(raw)} (expected {SHRM_DUMP_SIZE})"
        )
    digest = sha256(raw)
    if digest != SHRM_DUMP_SHA256:
        raise CoverageError(f"{SHRM_DUMP_NAME} hash mismatch: {digest}")

    sys.path.insert(0, str(REPO_ROOT))
    from tools import shrm_dump_decode

    plans = shrm_dump_decode.decode(raw)
    set_zero = {word.register for word in plans[0].words}
    union = {word.register for plan in plans for word in plan.words}
    return set_zero, union


def coverage_by_block(addresses: set[int], per_channel: dict[str, set[int]]) -> list[dict]:
    """Per block: report observed-span and full-block address densities."""
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
                "observed_span_address_density_percent": round(
                    100 * len(members) / span_slots, 4
                ),
                "full_64k_word_slot_density_percent": round(
                    100 * len(members) / WORD_SLOTS_PER_BLOCK, 4
                ),
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
            "observed_span_address_density_percent": round(
                100 * len(members) / span_slots, 4
            )
            if span_slots
            else 0.0,
            "full_64k_word_slot_density_percent": round(
                100 * len(members) / WORD_SLOTS_PER_BLOCK, 4
            ),
            "full_64k_word_slot_numerator": len(members),
            "full_64k_word_slot_denominator": WORD_SLOTS_PER_BLOCK,
            "ranked_offsets_observed": [
                f"0x{offset:x}" for offset in RANKED_OFFSETS if base + offset in members
            ],
        }
    slots = len(RANKED_BASES) * WORD_SLOTS_PER_BLOCK
    return {
        "per_instance": per_instance,
        "total_observed": total,
        "total_addressable_word_slots": slots,
        "full_64k_word_slot_density_percent": round(100 * total / slots, 4),
        "full_64k_word_slot_numerator": total,
        "full_64k_word_slot_denominator": slots,
    }


def build_manifest(firmware_dir: Path, dump_path: Path) -> dict:
    dependencies = dependency_manifest_hashes()
    dependency_files = dependency_file_hashes()
    counterexample_source = counterexample_provenance()
    data = load_xbl(firmware_dir)
    table = xbl_mc_table(data)
    if not dump_path.exists():
        raise CoverageError(f"missing SHRM dump: {dump_path.name}")
    set_zero, snapshot = shrm_snapshot_addresses(dump_path)

    channels = {"shrm_snapshot": snapshot, "xbl_mc_table": set(table)}
    union = set().union(*channels.values())
    counterexample = KNOWN_COUNTEREXAMPLE_ADDRESS
    return {
        "schema": SCHEMA,
        "experiment_id": "022-observation-coverage",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "image": XBL_NAME,
        "image_sha256": XBL_SHA256,
        "dependency_manifests": dependencies,
        "dependency_files": dependency_files,
        "shrm_dump": {
            "name": SHRM_DUMP_NAME,
            "size": SHRM_DUMP_SIZE,
            "sha256": SHRM_DUMP_SHA256,
        },
        "channels": {
            "shrm_snapshot_set0": len(set_zero),
            "shrm_snapshot_union": len(snapshot),
            "xbl_mc_table": len(table),
            "union": len(union),
            "xbl_table_addresses_new_to_the_snapshot": len(set(table) - snapshot),
        },
        "channel_scope": (
            "Exact counts for the two enumerated channels only: SHRM_MEM.BIN "
            "snapshot and Experiment 017 XBL MC table. This is not a complete "
            "project-nameable address set."
        ),
        "known_counterexample_to_completeness": {
            "address": f"0x{counterexample:08x}",
            "in_shrm_snapshot": counterexample in snapshot,
            "in_xbl_mc_table": counterexample in set(table),
            "in_enumerated_union": counterexample in union,
            "classification": "REFUTED",
            "source_manifest": counterexample_source["manifest"],
            "source_manifest_sha256": counterexample_source["sha256"],
            "source_field": counterexample_source["field"],
        },
        "completeness_conclusion": {
            "classification": "REFUTED",
            "scope": "two enumerated channels only",
            "counterexample": f"0x{counterexample:08x}",
            "global_project_nameable_set": "UNKNOWN",
        },
        "address_density_by_block": coverage_by_block(union, channels),
        "ranked_instances": ranked_instance_summary(union),
        "true_implemented_register_coverage": {
            "denominator": "UNKNOWN",
            "coverage": "UNKNOWN",
            "reason": "The implemented-register inventory is not available in these channels.",
        },
        "denominator_note": (
            "A 64-KiB block holds 16384 addressable word slots; the output reports "
            "observed-span address density and full-64-KiB word-slot density. The true "
            "implemented-register denominator and coverage are UNKNOWN."
        ),
        "claims": {
            "PROVED": [
                "The exact counts 430 (SHRM snapshot set 0), 470 (SHRM snapshot union), "
                "122 (Experiment 017 XBL MC table) and 492 (their union) describe the two "
                "enumerated channels only.",
                "Within each ranked MC instance the enumerated union contains 42 addresses "
                "over a 9305-word observed span, giving 0.4514 percent observed-span "
                "address density; its full-64-KiB word-slot density is 42/16384 = "
                "0.2563 percent per instance and 168/65536 = 0.2563 percent in the union.",
                "All three ranked offsets lie inside the selected sample; that is a property "
                "of how candidates were selected, not evidence of global coverage.",
            ],
            "SUPPORTED": [
                "The two enumerated channels provide a sparse observed sample around the "
                "ranked instances; the density figures are descriptive, not implemented-"
                "register coverage.",
            ],
            "REFUTED": [
                "The union of the two enumerated channels is the complete project-nameable "
                "controller-address set: known address 0x09248080 is outside both channels.",
            ],
            "UNKNOWN": [
                "How many registers each block actually implements, and therefore the true "
                "implemented-register denominator and coverage.",
                "Whether the bank relation is implemented by a register at all.",
                "Whether ranked-candidate negatives from other experiments generalize beyond "
                "these selected enumerated channels; these counts cannot establish global "
                "absence or quantify search coverage outside them.",
            ],
            "HYPOTHESIS": [
                "Repeating Experiment 014 timing recovery at another DDR operating point "
                "is one candidate follow-up; this experiment does not elevate it using the "
                "invalid completeness claim.",
            ],
        },
        "candidate_follow_up": {
            "name": "DDR-OPP timing recovery",
            "classification": "HYPOTHESIS",
            "scope": "one candidate discriminator only; no promotion or authority",
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--dump", type=Path, default=SHRM_DUMP)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing regular output file (default is no-clobber)",
    )
    return parser


def write_manifest(path: Path, manifest: dict, *, force: bool = False) -> None:
    """Write JSON with O_EXCL/O_NOFOLLOW by default."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(manifest, indent=1, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    if force:
        if path.exists() and not path.is_file():
            raise CoverageError(f"output is not a regular file: {path}")
        flags |= os.O_TRUNC
    else:
        flags |= os.O_EXCL
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise CoverageError(f"cannot create output without clobbering: {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
        os.chmod(path, 0o644)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir, args.dump)
    write_manifest(args.output, manifest, force=args.force)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
