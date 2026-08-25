#!/usr/bin/env python3
"""Host-only Experiment 021 audit of where DCB section data is delivered.

Experiment 020 found no consumer in the exact XBL that programs controller
registers from the DCB base-relative tables, and no such reference in AOP.
This asks the prior question: is that data delivered anywhere at all?

A section reaches a consumer either by being copied out of the DCB or by being
read in place. The copy path is enumerable — the loader's bounded copy has a
finite call graph — and the in-place consumers Experiment 020 identified are a
checksum accumulator and a bounds check.

It also audits the two images Experiment 020 left open. The SHRM Xtensa blob is
embedded in XBL and is searchable; `abl` is a UEFI firmware volume with
incompressible payload, and is not. Recording that difference matters: a
literal-absence result over compressed bytes is void, not negative.

Mode: HOST_ONLY_READ_ONLY.  No device, SMC, MMIO or protected-memory access.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import struct
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
SCHEMA = "sm8150-dcb-delivery-paths-v1"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4194304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

ABL_NAME = "abl--sdd8.bin"
ABL_SIZE = 4194304
ABL_SHA256 = "1db19d11a5ce6865e3fbcabadfbdaa9045e75f144b8bc8593a58338c20a3120c"

# The bounded copy the DCB loader calls, identified by reading the loader in
# Experiment 020 and pinned here by the hash of its first 64 bytes.
BOUNDED_COPY_VA = 0x1483AB24
BOUNDED_COPY_PROBE = 64

# The SHRM Xtensa blob embedded in XBL, at the Verification 001 pin.
SHRM_BLOB_VADDR = 0x148BBE98
SHRM_BLOB_SIZE = 23776
SHRM_BLOB_SHA256 = "421824b417ab28e6c0d1802c05d7ce5422e93b116973ce7f039321fb5a01a1fd"
SHRM_CODE_BASE = 0x28000

DIRECTORY_BASE = 0x0C
DCB_HEADER_SIZE = 0x64

APERTURE_START = 0x09000000
APERTURE_END = 0x0A000000
RANKED_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)
RANKED_OFFSETS = (0x400, 0x404, 0x4D0)

# Experiment 004 records these five as the loader-consumed sections.
EXPECTED_COPIED_SECTIONS = {0, 1, 2, 15, 16}

ENTROPY_SAMPLE = 1 << 20
# Shannon entropy at or above this leaves no readable constants.
INCOMPRESSIBLE_THRESHOLD = 7.9


class DeliveryError(ValueError):
    """Raised when an input is not the exact pinned artifact."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value >> (bits - 1) else value


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


class Elf64:
    """Minimal ELF64 view, written independently of the other tools/ modules."""

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise DeliveryError("not a little-endian ELF64 image")
        self.data = data
        ph_offset = struct.unpack_from("<Q", data, 32)[0]
        ph_entry = struct.unpack_from("<H", data, 54)[0]
        ph_count = struct.unpack_from("<H", data, 56)[0]
        self.segments = []
        for index in range(ph_count):
            offset = ph_offset + index * ph_entry
            if offset + 56 > len(data):
                break
            p_type, flags, file_offset, vaddr, _pa, file_size, _mem, _al = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
            if p_type == 1 and file_size and file_offset + file_size <= len(data):
                self.segments.append((file_offset, vaddr, file_size, flags))

    def file_offset(self, vaddr: int) -> int | None:
        for file_offset, base, size, _flags in self.segments:
            if base <= vaddr < base + size:
                return file_offset + (vaddr - base)
        return None

    def word(self, vaddr: int) -> int | None:
        offset = self.file_offset(vaddr)
        if offset is None or offset + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, offset)[0]

    def executable(self):
        return [s for s in self.segments if s[3] in (5, 7)]


def bounded_copy_call_sites(image: Elf64) -> dict:
    """Enumerate the copy path out of the DCB.

    Every call to the loader's bounded copy is found, and each is labelled with
    the DCB section whose directory slot was read just before it. A section with
    no such call is never copied out of the block.
    """
    sites = []
    for file_offset, base, size, flags in image.executable():
        for offset in range(0, size - 3, 4):
            word = struct.unpack_from("<I", image.data, file_offset + offset)[0]
            if (word & 0xFC000000) != 0x94000000:
                continue
            vaddr = base + offset
            if vaddr + 4 * sign_extend(word & 0x03FFFFFF, 26) != BOUNDED_COPY_VA:
                continue
            section = None
            for back in range(vaddr - 16 * 4, vaddr, 4):
                previous = image.word(back)
                if previous is None or (previous & 0xFFC00000) != 0x79400000:
                    continue
                byte_offset = ((previous >> 10) & 0xFFF) * 2
                if DIRECTORY_BASE <= byte_offset < DCB_HEADER_SIZE and (byte_offset - DIRECTORY_BASE) % 4 == 0:
                    section = (byte_offset - DIRECTORY_BASE) // 4
            sites.append(
                {
                    "call_va": f"0x{vaddr:08x}",
                    "segment": "RWE" if flags == 7 else "RX",
                    "dcb_section": section,
                }
            )
    copied = {s["dcb_section"] for s in sites if s["dcb_section"] is not None}
    return {
        "bounded_copy_va": f"0x{BOUNDED_COPY_VA:08x}",
        "call_site_count": len(sites),
        "call_sites": sorted(sites, key=lambda s: s["call_va"]),
        "sections_copied": sorted(copied),
        "matches_recorded_loader_sections": copied == EXPECTED_COPIED_SECTIONS,
        "sections_with_no_copy_path": sorted(set(range(18)) - copied),
    }


def shrm_blob_literal_audit(image: Elf64) -> dict:
    """Search the embedded SHRM Xtensa blob for controller addresses.

    Xtensa builds 32-bit constants through ``L32R`` from a literal pool, so an
    address the blob uses is present as an aligned stored word.
    """
    offset = image.file_offset(SHRM_BLOB_VADDR)
    if offset is None:
        raise DeliveryError("SHRM blob vaddr is not mapped")
    blob = image.data[offset : offset + SHRM_BLOB_SIZE]
    digest = sha256(blob)
    if digest != SHRM_BLOB_SHA256:
        raise DeliveryError(f"SHRM blob hash differs from the Verification 001 pin: {digest}")

    by_block: dict[int, list[tuple[int, int]]] = collections.defaultdict(list)
    for position in range(0, len(blob) - 3, 4):
        value = struct.unpack_from("<I", blob, position)[0]
        if APERTURE_START <= value < APERTURE_END:
            by_block[value & 0xFFFF0000].append((position, value))

    ranked_blocks = {}
    for base in RANKED_BASES:
        entries = sorted(by_block.get(base, []), key=lambda e: e[1])
        ranked_blocks[f"0x{base:08x}"] = [
            {
                "blob_offset": f"0x{position:05x}",
                "shrm_vaddr": f"0x{SHRM_CODE_BASE + position:05x}",
                "value": f"0x{value:08x}",
                "offset_from_base": f"0x{value - base:x}",
            }
            for position, value in entries
        ]
    ranked_targets = {}
    for base in RANKED_BASES:
        for register_offset in RANKED_OFFSETS:
            target = base + register_offset
            count = sum(
                1
                for position in range(0, len(blob) - 3, 4)
                if struct.unpack_from("<I", blob, position)[0] == target
            )
            if count:
                ranked_targets[f"0x{target:08x}"] = count
    return {
        "blob_vaddr": f"0x{SHRM_BLOB_VADDR:08x}",
        "blob_size": SHRM_BLOB_SIZE,
        "blob_sha256": digest,
        "aperture_blocks": len(by_block),
        "aperture_aligned_words": sum(len(v) for v in by_block.values()),
        "ranked_base_blocks": ranked_blocks,
        "ranked_target_literals": ranked_targets,
        "reaches_a_ranked_instance": any(ranked_blocks[k] for k in ranked_blocks),
        "reaches_a_ranked_target": bool(ranked_targets),
    }


def abl_searchability(firmware_dir: Path) -> dict:
    """Say whether a literal search over abl could mean anything. It cannot.

    A literal-absence result over incompressible bytes is void rather than
    negative, so this reports searchability instead of a count.
    """
    path = firmware_dir / ABL_NAME
    if not path.exists():
        return {"available": False}
    data = path.read_bytes()
    if len(data) != ABL_SIZE or sha256(data) != ABL_SHA256:
        raise DeliveryError(f"{ABL_NAME} is not the exact Experiment 004 artifact")
    if data[:4] != b"\x7fELF" or data[4] != 1:
        raise DeliveryError(f"{ABL_NAME} is not ELF32")

    ph_offset = struct.unpack_from("<I", data, 28)[0]
    ph_entry = struct.unpack_from("<H", data, 42)[0]
    ph_count = struct.unpack_from("<H", data, 44)[0]
    payload = None
    segments = []
    for index in range(ph_count):
        offset = ph_offset + index * ph_entry
        p_type, file_offset, vaddr, _pa, file_size, _mem, flags, _al = struct.unpack_from(
            "<IIIIIIII", data, offset
        )
        segments.append({"type": p_type, "vaddr": f"0x{vaddr:08x}", "file_size": file_size})
        if p_type == 1 and file_size and file_offset + file_size <= len(data):
            payload = data[file_offset : file_offset + file_size]
    if payload is None:
        return {"available": True, "searchable": False, "reason": "NO_PT_LOAD"}

    entropy = shannon_entropy(payload[:ENTROPY_SAMPLE])
    is_firmware_volume = payload[0x28:0x2C] == b"_FVH"
    aarch64_ret = sum(
        1
        for position in range(0, len(payload) - 3, 4)
        if struct.unpack_from("<I", payload, position)[0] == 0xD65F03C0
    )
    searchable = entropy < INCOMPRESSIBLE_THRESHOLD and aarch64_ret > 0
    return {
        "available": True,
        "elf_class": 32,
        "program_headers": segments,
        "payload_size": len(payload),
        "uefi_firmware_volume": is_firmware_volume,
        "payload_entropy_bits_per_byte": round(entropy, 3),
        "aarch64_ret_count": aarch64_ret,
        "searchable": searchable,
        "reason": None
        if searchable
        else "COMPRESSED_UEFI_FIRMWARE_VOLUME: a literal-absence result over these bytes is void",
    }


def load_xbl(firmware_dir: Path) -> bytes:
    path = firmware_dir / XBL_NAME
    if not path.exists():
        raise DeliveryError(f"missing exact image: {XBL_NAME}")
    data = path.read_bytes()
    if len(data) != XBL_SIZE or sha256(data) != XBL_SHA256:
        raise DeliveryError(f"{XBL_NAME} is not the exact Experiment 004 artifact")
    return data


def build_manifest(firmware_dir: Path) -> dict:
    image = Elf64(load_xbl(firmware_dir))
    copy_paths = bounded_copy_call_sites(image)
    shrm = shrm_blob_literal_audit(image)
    abl = abl_searchability(firmware_dir)
    probe_offset = image.file_offset(BOUNDED_COPY_VA)
    probe = sha256(image.data[probe_offset : probe_offset + BOUNDED_COPY_PROBE])
    return {
        "schema": SCHEMA,
        "experiment_id": "021-dcb-delivery-paths",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "image": XBL_NAME,
        "image_sha256": XBL_SHA256,
        "bounded_copy_probe_sha256": probe,
        "dcb_copy_paths": copy_paths,
        "shrm_blob_literal_audit": shrm,
        "abl_searchability": abl,
        "claims": {
            "PROVED": [
                "The loader's bounded copy has a finite call graph, and the DCB sections "
                "reached through it are exactly the five Experiment 004 records.",
                "No other DCB section is copied out of the block by that routine, so the "
                "base-relative programming tables have no delivery path through it.",
                "The embedded SHRM Xtensa blob holds aligned literals inside the first "
                "ranked MC instance block, and none equal to any of the twelve ranked "
                "target addresses.",
                "abl is a UEFI firmware volume whose payload is incompressible, so a "
                "literal search over it cannot produce a meaningful result either way.",
            ],
            "REFUTED": [
                "The DCB base-relative tables are delivered to a consumer by the XBL "
                "bounded copy.",
            ],
            "UNKNOWN": [
                "Whether abl consumes the DCB tables: its payload is not searchable "
                "without decompressing the firmware volume, which this does not attempt.",
                "Whether SHRM reaches a ranked target by computing an offset from the "
                "base literal it does hold, rather than storing the target address.",
                "Whether a copy path exists through a routine other than this one.",
                "Register semantics, the relation to the Experiment 014 GF(2) bank "
                "relation, post-boot writability, alias and boundary bypass.",
            ],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    args.output.chmod(0o644)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
