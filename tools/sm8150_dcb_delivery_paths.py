#!/usr/bin/env python3
"""Host-only Experiment 021 audit of where DCB section data is delivered.

Earlier narrow static passes looked for controller consumers through
constant-terminating models. Those models cannot see a writer whose base is a
runtime argument, so they do not establish absence. This experiment asks a
narrower question: what direct calls to one pinned bounded-copy routine can be
labelled from the instruction stream?

A section reaches a consumer either by being copied out of the DCB or by being
read in place. This experiment audits only one pinned bounded-copy routine and
the exact direct AArch64 BL/B encodings that target it. Indirect BLR/BR calls,
other copy routines and a global call graph are deliberately outside the
result. The in-place consumers Experiment 020 identified are a checksum
accumulator and a bounds check.

It also audits the two images Experiment 020 left open. The SHRM Xtensa blob is
embedded in XBL and receives a bounded aligned-literal audit; `abl` is recorded
as an unparsed UEFI firmware volume with high measured entropy. Recording that
difference matters: a literal-absence result over unparsed bytes is void, not
negative.

Mode: HOST_ONLY_READ_ONLY.  No device, SMC, MMIO or protected-memory access.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import struct
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
SCHEMA = "sm8150-dcb-delivery-paths-v2"

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
# This is an observation threshold, not a compression or searchability proof.
INCOMPRESSIBLE_THRESHOLD = 7.9

# Public manifests are inputs to the provenance claim. Keep their hashes
# pinned so a changed dependency cannot silently alter this result.
MANIFEST_DIR = REPO_ROOT / "evidence/manifests"
DEPENDENCY_MANIFESTS = {
    "004-live-firmware-readonly-20260825-01.manifest.json":
        "1ed4b8b14b2e0ccf2d4ae084ea413e0395d9dc488dd5d2bb1dd872fbe20d9247",
    "verification-001-independent-claim-audit-20260825-01.manifest.json":
        "a722f0f66367de300b9a4402002e510a0d457c0250ca1b09f44e964f4914f2e5",
}


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


def dependency_manifest_hashes(manifest_dir: Path = MANIFEST_DIR) -> dict[str, str]:
    """Validate and return every public manifest hash this experiment uses."""

    result = {}
    for name, expected in DEPENDENCY_MANIFESTS.items():
        path = manifest_dir / name
        if not path.is_file():
            raise DeliveryError(f"missing dependency manifest: {name}")
        actual = sha256(path.read_bytes())
        if actual != expected:
            raise DeliveryError(f"dependency manifest hash mismatch for {name}: {actual}")
        result[name] = actual
    return result


def _direct_branch_target(word: int, vaddr: int) -> tuple[str, int] | None:
    """Decode only direct AArch64 B and BL, preserving their distinction."""

    opcode = word & 0xFC000000
    if opcode == 0x94000000:
        kind = "BL"
    elif opcode == 0x14000000:
        kind = "B"
    else:
        return None
    return kind, vaddr + 4 * sign_extend(word & 0x03FFFFFF, 26)


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
    """Audit direct BL/B edges to the one pinned bounded-copy routine.

    This is intentionally a direct-branch census, not a whole call-graph
    proof. Each direct BL site is examined for a nearby directory read and is
    labelled only when that local pattern is present. Unlabelled direct BL
    sites, indirect BLR/BR callers and other routines that may copy data leave
    delivery UNKNOWN.
    """
    sites = []
    direct_bl_sites = []
    direct_b_sites = []
    for file_offset, base, size, flags in image.executable():
        for offset in range(0, size - 3, 4):
            word = struct.unpack_from("<I", image.data, file_offset + offset)[0]
            branch = _direct_branch_target(word, base + offset)
            if branch is None:
                continue
            vaddr = base + offset
            kind, target = branch
            if target != BOUNDED_COPY_VA:
                continue
            entry = {"branch_va": f"0x{vaddr:08x}", "target_va": f"0x{target:08x}"}
            if kind == "BL":
                direct_bl_sites.append(entry)
            else:
                direct_b_sites.append(entry)
            if kind != "BL":
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
    locally_labelled = {
        s["dcb_section"] for s in sites if s["dcb_section"] is not None
    }
    unlabelled_direct_bl_sites = [
        site for site in sites if site["dcb_section"] is None
    ]
    return {
        "bounded_copy_va": f"0x{BOUNDED_COPY_VA:08x}",
        "scope": (
            "exact pinned routine, direct BL/B encodings and local directory-read "
            "labels only; unlabelled direct BL sites, indirect BLR/BR callers and "
            "other copy routines leave delivery UNKNOWN"
        ),
        "call_site_count": len(sites),
        "direct_bl_count": len(direct_bl_sites),
        "direct_b_count": len(direct_b_sites),
        "unlabelled_direct_bl_count": len(unlabelled_direct_bl_sites),
        "unlabelled_direct_bl_sites": [
            site["call_va"] for site in unlabelled_direct_bl_sites
        ],
        "direct_bl_sites": sorted(direct_bl_sites, key=lambda s: s["branch_va"]),
        "direct_b_sites": sorted(direct_b_sites, key=lambda s: s["branch_va"]),
        "call_sites": sorted(sites, key=lambda s: s["call_va"]),
        "locally_labelled_sections": sorted(locally_labelled),
        "matches_recorded_locally_labelled_sections": (
            locally_labelled == EXPECTED_COPIED_SECTIONS
        ),
        "sections_without_locally_labelled_direct_path": sorted(
            set(range(18)) - locally_labelled
        ),
    }


def shrm_blob_literal_audit(image: Elf64) -> dict:
    """Search the embedded SHRM Xtensa blob for controller addresses.

    This is an aligned stored-word census over the Xtensa blob. Literal
    presence or absence bounds only stored constants; a target formed by
    arithmetic from a base or another runtime value remains UNKNOWN.
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

    ranked_block_literals = {}
    for base in RANKED_BASES:
        entries = sorted(by_block.get(base, []), key=lambda e: e[1])
        ranked_block_literals[f"0x{base:08x}"] = [
            {
                "blob_offset": f"0x{position:05x}",
                "shrm_vaddr": f"0x{SHRM_CODE_BASE + position:05x}",
                "value": f"0x{value:08x}",
                "offset_from_base": f"0x{value - base:x}",
            }
            for position, value in entries
        ]
    ranked_target_counts = {}
    for base in RANKED_BASES:
        for register_offset in RANKED_OFFSETS:
            target = base + register_offset
            count = sum(
                1
                for position in range(0, len(blob) - 3, 4)
                if struct.unpack_from("<I", blob, position)[0] == target
            )
            ranked_target_counts[f"0x{target:08x}"] = count
    ranked_block_literal_counts = {
        key: len(entries) for key, entries in ranked_block_literals.items()
    }
    return {
        "blob_vaddr": f"0x{SHRM_BLOB_VADDR:08x}",
        "blob_size": SHRM_BLOB_SIZE,
        "blob_sha256": digest,
        "aperture_blocks": len(by_block),
        "aperture_aligned_words": sum(len(v) for v in by_block.values()),
        "ranked_instance_block_literals": ranked_block_literals,
        "ranked_instance_block_literal_counts": ranked_block_literal_counts,
        # Keep the historical non-zero-only view, and add an explicit all-zero
        # census so absence is an exact count rather than an empty-map hint.
        "ranked_target_literals": {
            key: count for key, count in ranked_target_counts.items() if count
        },
        "ranked_target_literal_counts": ranked_target_counts,
        "ranked_target_literal_total": sum(ranked_target_counts.values()),
        "ranked_instance_block_literal_present": any(
            ranked_block_literals[k] for k in ranked_block_literals
        ),
        "ranked_target_literal_present": bool(sum(ranked_target_counts.values())),
    }


def abl_searchability(firmware_dir: Path) -> dict:
    """Record raw ABL observations without promoting them to a decode result.

    An aligned ``_FVH``, high measured entropy and zero aligned AArch64 RET
    words are observations. Whether the payload is compressed, and whether a
    literal search would be meaningful after parsing it, remains UNKNOWN.
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
        return {
            "available": True,
            "classification": "UNPARSED_ELF32_NO_PT_LOAD",
            "searchability": "UNKNOWN",
            "searchable": None,
            "reason": "No PT_LOAD payload was available for a literal search",
        }

    entropy = shannon_entropy(payload[:ENTROPY_SAMPLE])
    is_firmware_volume = payload[0x28:0x2C] == b"_FVH"
    aligned_aarch64_ret = sum(
        1
        for position in range(0, len(payload) - 3, 4)
        if struct.unpack_from("<I", payload, position)[0] == 0xD65F03C0
    )
    high_entropy = entropy >= INCOMPRESSIBLE_THRESHOLD
    classification = (
        "UNPARSED_HIGH_ENTROPY_UEFI_FV"
        if is_firmware_volume and high_entropy
        else "UNPARSED_ELF32_PAYLOAD"
    )
    return {
        "available": True,
        "artifact_name": ABL_NAME,
        "artifact_size": len(data),
        "artifact_sha256": sha256(data),
        "elf_class": 32,
        "program_headers": segments,
        "payload_size": len(payload),
        "fvh_marker_present": is_firmware_volume,
        "fvh_marker_offset": "0x28" if is_firmware_volume else None,
        "firmware_volume_parse": "NOT_PERFORMED",
        "payload_entropy_bits_per_byte": round(entropy, 3),
        "entropy_sample_size": min(ENTROPY_SAMPLE, len(payload)),
        "entropy_scope": "first 1048576 payload bytes",
        "entropy_threshold_bits_per_byte": INCOMPRESSIBLE_THRESHOLD,
        "entropy_at_or_above_threshold": high_entropy,
        "aarch64_ret_count": aligned_aarch64_ret,
        "aligned_aarch64_ret_count": aligned_aarch64_ret,
        "classification": classification,
        "searchability": "UNKNOWN",
        # Kept as a false-y compatibility field; the semantic status above is
        # intentionally UNKNOWN rather than a threshold-derived bool.
        "searchable": None,
        "reason": (
            "HIGH_ENTROPY_UEFI_FV_REQUIRES_PARSING: compression and literal "
            "searchability are UNKNOWN; a literal-absence result is void"
        ),
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
    dependencies = dependency_manifest_hashes()
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
        "dependency_manifests": dependencies,
        "bounded_copy_probe_sha256": probe,
        "direct_branch_census": {
            "target_va": f"0x{BOUNDED_COPY_VA:08x}",
            "direct_bl_count": copy_paths["direct_bl_count"],
            "direct_b_count": copy_paths["direct_b_count"],
        },
        "dcb_copy_paths": copy_paths,
        "delivery_conclusion": {
            "classification": "UNKNOWN",
            "scope": (
                "pinned bounded-copy routine, direct BL/B census and local "
                "directory-read labels only"
            ),
            "local_label_status": "NOT_OBSERVED",
            "sections_without_locally_labelled_direct_path": copy_paths[
                "sections_without_locally_labelled_direct_path"
            ],
            "sections_without_locally_labelled_direct_path_status": "NOT_OBSERVED",
            "unlabelled_direct_bl_count": copy_paths["unlabelled_direct_bl_count"],
            "direct_delivery": "UNKNOWN",
            "global_delivery": "UNKNOWN",
            "indirect_blr_br": "UNKNOWN",
            "other_copy_routines": "UNKNOWN",
        },
        "shrm_blob_literal_audit": shrm,
        "abl_searchability": abl,
        "claim_scope": (
            "Delivery conclusions are limited to the pinned bounded-copy routine "
            "and its direct BL/B census in the exact XBL."
        ),
        "claims": {
            "PROVED": [
                "The exact XBL has seven direct BL edges to the pinned bounded-copy "
                "routine and zero direct B edges to it.",
                "Under the local directory-read label model, five direct BL sites are "
                "labelled with sections exactly {0, 1, 2, 15, 16}, matching the "
                "Experiment 004 record.",
                "Sections 3-14 and 17 are NOT_OBSERVED in the local directory-read label "
                "model; direct delivery through the two unlabelled calls remains UNKNOWN.",
                "The embedded SHRM Xtensa blob holds aligned literals inside the first "
                "ranked MC instance block, and none equal to any of the twelve ranked "
                "target addresses.",
                "abl has an aligned _FVH marker, measured entropy at or above the "
                "pinned threshold in the first 1048576 payload bytes, and zero "
                "aligned AArch64 RET observations.",
            ],
            "SUPPORTED": [
                "The ABL observations support the UNPARSED_HIGH_ENTROPY_UEFI_FV "
                "classification, but do not prove compression or semantic "
                "unsearchability.",
            ],
            "REFUTED": [
                "The local directory-read label model accounts for every direct BL call "
                "site; two of the seven direct BL sites are unlabelled.",
            ],
            "UNKNOWN": [
                "Whether abl consumes the DCB tables, whether its payload is compressed, "
                "and whether a literal search would be meaningful after parsing it.",
                "Whether SHRM reaches a ranked target by computing an offset from the "
                "base literal it does hold, rather than storing the target address.",
                "Whether direct delivery of sections 3-14 or 17 occurs through the two "
                "unlabelled calls; whether an indirect BLR/BR caller reaches the pinned "
                "routine; whether a copy path exists through another routine; and any "
                "global call-graph conclusion.",
                "Register semantics, the relation to the Experiment 014 GF(2) bank "
                "relation, post-boot writability, alias and boundary bypass.",
            ],
            "HYPOTHESIS": [],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing regular output file (default is no-clobber)",
    )
    return parser


def write_manifest(path: Path, manifest: dict, *, force: bool = False) -> None:
    """Write JSON with O_EXCL/O_NOFOLLOW by default.

    A checked-in evidence file must not be silently replaced by a rerun. An
    explicit ``--force`` is required for deliberate regeneration, and even
    that path refuses symlinks.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(manifest, indent=1, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    if force:
        if path.exists() and not path.is_file():
            raise DeliveryError(f"output is not a regular file: {path}")
        flags |= os.O_TRUNC
    else:
        flags |= os.O_EXCL
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise DeliveryError(f"cannot create output without clobbering: {path}: {exc}") from exc
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
    manifest = build_manifest(args.firmware_dir)
    write_manifest(args.output, manifest, force=args.force)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
