#!/usr/bin/env python3
"""Host-only Experiment 018 Stage 1A store-offset census.

This tool inventories exact target/base literals and counts only strict
AArch64 ``STR W/Xt,[Xn,#imm]`` unsigned-immediate candidates in file-backed
PT_LOAD words.  It does not resolve base registers, infer writers, follow
control flow, access a device, or emit firmware bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Iterable

try:
    from tools.sm8150_xbl_mc_snapshot_xref import ElfImage, Segment
except ModuleNotFoundError as error:  # direct ``python tools/...`` invocation
    if error.name != "tools":
        raise
    from sm8150_xbl_mc_snapshot_xref import ElfImage, Segment


REPO_ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
DEFAULT_XBL = FIRMWARE_DIR / "xbl--sdb1.bin"

XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

TARGET_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)
TARGET_OFFSETS = (0x400, 0x404, 0x4D0)
TARGETS = tuple(base + offset for base in TARGET_BASES for offset in TARGET_OFFSETS)

EXP017_TABLE_FILE_OFFSET = 0x630B8
EXP017_TABLE_VADDR = 0x146B1218
EXP017_TABLE_BYTE_LENGTH = 984
EXP017_TABLE_FILE_END = EXP017_TABLE_FILE_OFFSET + EXP017_TABLE_BYTE_LENGTH


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: int, width: int | None = None) -> str:
    return f"0x{value:0{width}x}" if width else f"0x{value:x}"


def _find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return hits
        hits.append(offset)
        cursor = offset + 1


def _segment_class(segment: Segment) -> str:
    if segment.executable and segment.flags & 2:
        return "RWE"
    if segment.executable:
        return "RX"
    if segment.flags & 2:
        return "RW"
    return "OTHER"


def _iter_segment_words(image: ElfImage, segment: Segment) -> Iterable[tuple[int, int, int]]:
    end = segment.offset + segment.filesz
    first = segment.offset
    while first < end and (segment.vaddr + first - segment.offset) & 3:
        first += 1
    for file_offset in range(first, end - 3, 4):
        yield (
            segment.vaddr + file_offset - segment.offset,
            file_offset,
            struct.unpack_from("<I", image.data, file_offset)[0],
        )


def _mapped_va(image: ElfImage, file_offset: int, width: int) -> int | None:
    try:
        return image.offset_to_vaddr(file_offset, width)
    except ValueError:
        return None


def _literal_occurrence(image: ElfImage, file_offset: int, width: int) -> dict[str, object]:
    va = _mapped_va(image, file_offset, width)
    segment_class = None
    if va is not None:
        try:
            segment_class = _segment_class(image.segment_for_vaddr(va, width))
        except ValueError:
            segment_class = None
    in_table = (
        EXP017_TABLE_FILE_OFFSET <= file_offset
        and file_offset + width <= EXP017_TABLE_FILE_END
    )
    return {
        "file_offset": _hex(file_offset),
        "virtual_address": _hex(va) if va is not None else None,
        "segment_class": segment_class,
        "aligned_file_offset": file_offset % width == 0,
        "aligned_virtual_address": va is not None and va % width == 0,
        "source": "experiment_017_table" if in_table else "other_file_literal",
    }


def literal_inventory(image: ElfImage) -> dict[str, object]:
    entries = []
    for kind, values in (("base", TARGET_BASES), ("target", TARGETS)):
        for value in values:
            u32_offsets = _find_all(image.data, struct.pack("<I", value))
            u64_offsets = _find_all(image.data, struct.pack("<Q", value))
            u32 = [_literal_occurrence(image, offset, 4) for offset in u32_offsets]
            u64 = [_literal_occurrence(image, offset, 8) for offset in u64_offsets]
            entries.append(
                {
                    "kind": kind,
                    "value": _hex(value, 8),
                    "u32": {
                        "count": len(u32),
                        "aligned_count": sum(item["aligned_file_offset"] for item in u32),
                        "aligned_file_offset_count": sum(item["aligned_file_offset"] for item in u32),
                        "aligned_virtual_address_count": sum(item["aligned_virtual_address"] for item in u32),
                        "occurrences": u32,
                    },
                    "u64": {
                        "count": len(u64),
                        "aligned_count": sum(item["aligned_file_offset"] for item in u64),
                        "aligned_file_offset_count": sum(item["aligned_file_offset"] for item in u64),
                        "aligned_virtual_address_count": sum(item["aligned_virtual_address"] for item in u64),
                        "occurrences": u64,
                    },
                }
            )
    return {
        "table_file_offset": _hex(EXP017_TABLE_FILE_OFFSET),
        "table_virtual_address": _hex(EXP017_TABLE_VADDR),
        "table_byte_length": EXP017_TABLE_BYTE_LENGTH,
        "table_file_end_offset": _hex(EXP017_TABLE_FILE_END),
        "values": entries,
        "base_literal_count": len(TARGET_BASES),
        "target_literal_count": len(TARGETS),
    }


def _decode_str_unsigned_immediate(word: int) -> dict[str, object] | None:
    """Decode only scalar STR B/H/W/X unsigned-immediate; reject loads/SIMD."""

    # Bits 29:24 select the scalar unsigned-immediate class, bit 26 is V,
    # and bits 23:22 select the store opcode.  Including all of bits 29:22
    # rejects SIMD/FP and the non-store opc values (including signed loads).
    if word & 0x3FC00000 != 0x39000000:
        return None
    size = (word >> 30) & 0x3
    if size not in (2, 3):
        return None  # Stage 1A is deliberately W/X only.
    width = 1 << size
    return {
        "form": "STR_UNSIGNED_IMMEDIATE",
        "width_bytes": width,
        "byte_offset": ((word >> 10) & 0xFFF) * width,
        "base_register": (word >> 5) & 0x1F,
        "source_register": word & 0x1F,
        "base_is_sp": ((word >> 5) & 0x1F) == 31,
    }


def _census(image: ElfImage) -> dict[str, object]:
    segment_rows = []
    counts = {"RX": 0, "RWE": 0, "RW": 0, "OTHER": 0}
    word_counts = {"RX": 0, "RWE": 0, "RW": 0, "OTHER": 0}
    recognized = {"RX": 0, "RWE": 0}
    matching_offsets = {"RX": {"0x400": 0, "0x404": 0, "0x4d0": 0}, "RWE": {"0x400": 0, "0x404": 0, "0x4d0": 0}}
    candidates: list[dict[str, object]] = []

    for segment in image.segments:
        class_name = _segment_class(segment)
        counts[class_name] += 1
        words = list(_iter_segment_words(image, segment))
        word_counts[class_name] += len(words)
        segment_rows.append(
            {
                "class": class_name,
                "file_offset": _hex(segment.offset),
                "virtual_address": _hex(segment.vaddr),
                "file_size": segment.filesz,
                "flags": segment.flags,
                "aligned_word_count": len(words),
            }
        )
        if class_name not in recognized:
            continue
        for virtual_address, file_offset, word in words:
            decoded = _decode_str_unsigned_immediate(word)
            if decoded is None:
                continue
            recognized[class_name] += 1
            offset = int(decoded["byte_offset"])
            offset_key = _hex(offset)
            if offset_key in matching_offsets[class_name]:
                matching_offsets[class_name][offset_key] += 1
                candidates.append(
                    {
                        "segment_class": class_name,
                        "virtual_address": _hex(virtual_address),
                        "file_offset": _hex(file_offset),
                        "byte_offset": offset_key,
                        "width_bytes": decoded["width_bytes"],
                        "base_register": (
                            "SP"
                            if decoded["base_register"] == 31
                            else f"X{decoded['base_register']}"
                        ),
                        "source_register": f"W{decoded['source_register']}" if decoded["width_bytes"] == 4 else f"X{decoded['source_register']}",
                        "base_is_sp": decoded["base_is_sp"],
                        "exact_target_resolution": None,
                        "status": "OFFSET_MATCH_ONLY_UNRESOLVED_BASE",
                    }
                )
    candidates.sort(key=lambda row: (row["segment_class"], int(str(row["file_offset"]), 16)))
    return {
        "segments": segment_rows,
        "segment_counts": counts,
        "aligned_word_counts": word_counts,
        "recognized_str_wx_counts": recognized,
        "matching_offsets_by_segment": matching_offsets,
        "matching_offset_candidate_count": len(candidates),
        "matching_offset_candidate_count_by_segment": {
            class_name: sum(
                count for count in matching_offsets[class_name].values()
            )
            for class_name in ("RX", "RWE")
        },
        "candidates": candidates,
        "unsupported_forms": {
            "count": None,
            "status": "NOT_COUNTED_STAGE1A",
            "reason": "Stage 1A only decodes scalar STR W/X unsigned-immediate; all other store forms remain unmodeled/UNKNOWN.",
        },
        "rwe_decodes_are_ambiguous": True,
    }


def analyze(data: bytes) -> dict[str, object]:
    if len(data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(data)}, expected {XBL_SIZE}")
    image_hash = sha256(data)
    if image_hash != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 mismatch: {image_hash}")
    image = ElfImage(data)
    literals = literal_inventory(image)
    census = _census(image)
    return {
        "schema": "sdm855-xbl-mc-writer-xref-public-v1",
        "stage": "STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "input": {
            "filename": "xbl--sdb1.bin",
            "size": len(data),
            "sha256": image_hash,
            "pin_verified": True,
        },
        "target_set": {
            "base_count": len(TARGET_BASES),
            "offsets": [_hex(value) for value in TARGET_OFFSETS],
            "target_count": len(TARGETS),
            "bases": [_hex(value, 8) for value in TARGET_BASES],
            "targets": [_hex(value, 8) for value in TARGETS],
        },
        "literal_inventory": literals,
        "pt_load_census": census,
        "model": {
            "resolved_target_hit_count": None,
            "base_resolution": "NOT_ATTEMPTED_STAGE1A",
            "effective_address_resolution": "NOT_ATTEMPTED_STAGE1A",
            "limitations": [
                "No base-register or effective-address resolution is performed in Stage 1A.",
                "No cross-instruction, cross-block, cross-call, table-derived, argument-derived, or dynamic provenance is resolved.",
                "RWE words are ambiguous and never promoted to proved instructions.",
                "STUR, pre/post-index, register-offset, STP, literal loads, and other store forms remain unsupported/UNKNOWN.",
            ],
        },
        "claims": {
            "PROVED": [
                "The exact pinned XBL and exact 12-target/four-base set are bound by hash and constants.",
                "The public literal inventory records deterministic u32/u64 occurrences, alignment, file offsets, mapped VAs, and Experiment-017 table membership.",
                "The PT_LOAD census separates RX from ambiguous RWE/RW/OTHER file-backed words, and the store census recognizes only strict scalar STR W/X unsigned-immediate forms.",
            ],
            "REFUTED": [],
            "UNKNOWN": [
                "Whether any literal or offset-matching store is a writer; literal presence and offset matching are not store/base resolution.",
                "All cross-block, cross-call, argument-derived, table-derived, dynamic-base, unsupported-form, and RWE paths.",
                "Actual writer identity, execution, register semantics, mutability/lock, GF(2) relation, alias/bypass, and AOP/TZ/other-firmware paths.",
            ],
        },
        "classification": "STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN",
    }


def analyze_path(path: Path) -> dict[str, object]:
    result = analyze(path.read_bytes())
    result["input"] = {**result["input"], "filename": path.name}
    return result


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_no_clobber(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xbl", type=Path, default=DEFAULT_XBL)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    write_no_clobber(args.output, _json_bytes(analyze_path(args.xbl)))
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
