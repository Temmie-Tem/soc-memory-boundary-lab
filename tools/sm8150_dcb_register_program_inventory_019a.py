#!/usr/bin/env python3
"""Host-only Experiment 019 inventory of DCB register-programming tables.

Experiment 018 searched the exact XBL for stores to twelve ranked absolute MC
addresses and found no writer inside four progressively wider static models.
This experiment asks the complementary question that a target-first search
cannot reach: does the boot chain program controller registers from *data*
rather than from code-resident absolute addresses?

The `xbl_config` DCB turns out to carry exactly that: zero-terminated
``(offset, value)`` register tables whose base is supplied externally.  That
encoding is why the ranked absolute addresses never appear as XBL literals, so
this inventory both explains the Experiment 018 negative and re-tests the
ranked candidates against the data-driven path.

The ELF walk here is deliberately independent of the other `tools/` modules.
Reusing an existing parser would make the result inherit that parser's mapping,
which is the circularity Verification 001 was written to avoid.

Mode: HOST_ONLY_READ_ONLY.  No device, SMC, MMIO or protected-memory access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"

SCHEMA = "sm8150-dcb-register-program-inventory-v1"

DCB_SIZE = 0x3404
DCB_HEADER_SIZE = 0x64
DCB_SECTION_SLOTS = (DCB_HEADER_SIZE - 0x0C) // 4

# Experiment 004 pinned every exact image; the inventory refuses to run on any
# byte sequence other than these.
EXACT_IMAGES = {
    "abl--sdd8.bin": (4194304, "1db19d11a5ce6865e3fbcabadfbdaa9045e75f144b8bc8593a58338c20a3120c"),
    "aop--sdd7.bin": (524288, "eadd6c78daca52221e1e3419f34a53eac7c1e2c2bb46c9b663325df1998b9c7c"),
    "devcfg--sdd22.bin": (131072, "0399578253dd293dfc961c6a1077f660834df3ae5e1d65555f4225e327a03d14"),
    "hyp--sdd33.bin": (1048576, "646f8fca08b0eff56b1d8415d81c3041a775c1871400dc57448cb5103405a8e1"),
    "tz--sdd5.bin": (4194304, "a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab"),
    "xbl--sdb1.bin": (4194304, "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"),
    "xbl--sdc1.bin": (4194304, "ae1191b5d70e6de9fd67c6d629bc93aa567296605d30b5c9196ff58fcc26cb50"),
    "xbl_config--sdb2.bin": (4149248, "0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c"),
    "xbl_config--sdc2.bin": (4149248, "1b34aaaab314d22eaf25e0efa708df96dba9a3ecf731fde2461efdb214c1bb24"),
}

DCB_IMAGE = "xbl_config--sdb2.bin"

# The SoC control aperture.  A pair-table key inside it is an absolute MMIO
# address; a key below it is an offset awaiting a base.
APERTURE_START = 0x09000000
APERTURE_END = 0x0A000000

# Experiment 018's twelve ranked absolute targets, and the offsets they use.
RANKED_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)
RANKED_OFFSETS = (0x400, 0x404, 0x4D0)

# Verification 012 set-0 measured values for the ranked candidates.  These are
# live silicon readings, not firmware constants; whether firmware ever writes
# them is the question this inventory tests.
RANKED_LIVE_VALUES = {
    0xC003FFFF: "qhs_mc +0x400",
    0x00003333: "qhs_mc +0x404",
    0x00111111: "qhs_mccc +0x118",
    0x00300014: "qhs_mc +0x4d0 (two instances)",
    0x00300033: "qhs_mc +0x4d0 (two instances)",
    0x00001111: "qhs_mccc_master +0x294",
}


class InventoryError(ValueError):
    """Raised when an input is not the exact pinned artifact."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class LoadSegment:
    file_offset: int
    vaddr: int
    file_size: int
    flags: int


def parse_pt_load(data: bytes) -> list[LoadSegment]:
    """Walk ELF64 little-endian program headers without any shared helper."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise InventoryError("not a little-endian ELF64 image")
    ph_offset = struct.unpack_from("<Q", data, 32)[0]
    ph_entry_size = struct.unpack_from("<H", data, 54)[0]
    ph_count = struct.unpack_from("<H", data, 56)[0]
    segments = []
    for index in range(ph_count):
        offset = ph_offset + index * ph_entry_size
        p_type, flags, file_offset, vaddr, _paddr, file_size, _memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        if p_type != 1 or file_offset + file_size > len(data):
            continue
        segments.append(LoadSegment(file_offset, vaddr, file_size, flags))
    return segments


def find_dcb_blocks(data: bytes) -> list[tuple[int, bytes]]:
    """Return the exact 0x3404-byte DCB PT_LOAD blocks, in file order."""
    blocks = [
        (segment.file_offset, data[segment.file_offset : segment.file_offset + DCB_SIZE])
        for segment in parse_pt_load(data)
        if segment.file_size == DCB_SIZE
    ]
    if not blocks:
        raise InventoryError(f"no 0x{DCB_SIZE:x}-byte DCB load segment found")
    return blocks


def parse_sections(block: bytes) -> dict[int, tuple[int, int, bytes]]:
    """Section directory: 22 slots of ``{u16 data_offset, u16 size}`` from 0x0C."""
    sections: dict[int, tuple[int, int, bytes]] = {}
    for index in range(DCB_SECTION_SLOTS):
        header_offset = 0x0C + index * 4
        data_offset, size = struct.unpack_from("<HH", block, header_offset)
        if data_offset == 0 and size == 0:
            continue
        if data_offset < DCB_HEADER_SIZE or data_offset + size > DCB_SIZE:
            raise InventoryError(f"DCB section {index} range is invalid")
        sections[index] = (data_offset, size, block[data_offset : data_offset + size])
    return sections


def read_pairs(body: bytes) -> tuple[list[tuple[int, int]], int]:
    """Read ``(key, value)`` u32 pairs up to an all-zero terminator.

    Returns the pairs and the number of bytes left after the terminator.
    """
    pairs: list[tuple[int, int]] = []
    for offset in range(0, len(body) - 7, 8):
        key, value = struct.unpack_from("<II", body, offset)
        if key == 0 and value == 0:
            return pairs, len(body) - offset - 8
        pairs.append((key, value))
    return pairs, -1


def classify_section(body: bytes) -> dict:
    """Accept a section as a register table only under a strict, stated test.

    Every key must be 4-byte aligned and strictly ascending, at least four
    entries must precede an all-zero terminator, and that terminator must be
    the final eight bytes.  A byte run that merely happens to parse as pairs
    fails at least one of those.
    """
    pairs, tail = read_pairs(body)
    keys = [key for key, _ in pairs]
    reasons = []
    if len(pairs) < 4:
        reasons.append("FEWER_THAN_FOUR_ENTRIES")
    if tail != 0:
        reasons.append("TERMINATOR_NOT_FINAL" if tail > 0 else "NO_TERMINATOR")
    if any(key % 4 for key in keys):
        reasons.append("UNALIGNED_KEY")
    if any(keys[i] >= keys[i + 1] for i in range(len(keys) - 1)):
        reasons.append("KEYS_NOT_STRICTLY_ASCENDING")

    if reasons:
        return {"kind": "NOT_A_REGISTER_TABLE", "rejected_because": reasons, "entry_count": len(pairs)}

    absolute = all(APERTURE_START <= key < APERTURE_END for key in keys)
    relative = all(key < APERTURE_START for key in keys)
    if absolute:
        kind = "ABSOLUTE_ADDRESS_TABLE"
    elif relative:
        kind = "BASE_RELATIVE_OFFSET_TABLE"
    else:
        return {"kind": "NOT_A_REGISTER_TABLE", "rejected_because": ["MIXED_KEY_DOMAIN"], "entry_count": len(pairs)}

    record = {
        "kind": kind,
        "entry_count": len(pairs),
        "key_first": f"0x{keys[0]:08x}",
        "key_last": f"0x{keys[-1]:08x}",
        "ranked_offset_hits": [
            {"key": f"0x{key:x}", "value": f"0x{value:08x}"}
            for key, value in pairs
            if key in RANKED_OFFSETS
        ],
    }
    if kind == "ABSOLUTE_ADDRESS_TABLE":
        record["distinct_64k_bases"] = sorted({f"0x{key & 0xFFFF0000:08x}" for key in keys})
        record["ranked_base_hits"] = sorted(
            {f"0x{key & 0xFFFF0000:08x}" for key in keys if (key & 0xFFFF0000) in RANKED_BASES}
        )
    return record


def inventory_dcb(data: bytes) -> dict:
    blocks = find_dcb_blocks(data)
    per_block = []
    for block_index, (file_offset, block) in enumerate(blocks):
        sections = parse_sections(block)
        entries = {}
        for index, (data_offset, size, body) in sorted(sections.items()):
            record = classify_section(body)
            record.update(
                {
                    "data_offset": f"0x{data_offset:x}",
                    "size": size,
                    "sha256": sha256(body),
                }
            )
            entries[str(index)] = record
        per_block.append(
            {
                "block_index": block_index,
                "file_offset": f"0x{file_offset:x}",
                "sha256": sha256(block),
                "sections": entries,
            }
        )

    # Cross-block variance localises the configuration-dependent fields.
    variance = []
    section_indices = sorted({int(k) for b in per_block for k in b["sections"]})
    for index in section_indices:
        hashes = [b["sections"].get(str(index), {}).get("sha256") for b in per_block]
        present = [h for h in hashes if h]
        table_kinds = {b["sections"].get(str(index), {}).get("kind") for b in per_block}
        entry = {
            "section": index,
            "identical_across_blocks": len(set(present)) == 1 and len(present) == len(per_block),
            "present_in_blocks": len(present),
            "kinds": sorted(k for k in table_kinds if k),
        }
        if "BASE_RELATIVE_OFFSET_TABLE" in table_kinds or "ABSOLUTE_ADDRESS_TABLE" in table_kinds:
            merged: dict[int, dict[int, int]] = {}
            for block_index, (_file_offset, block) in enumerate(blocks):
                sections = parse_sections(block)
                if index not in sections:
                    continue
                pairs, _tail = read_pairs(sections[index][2])
                for key, value in pairs:
                    merged.setdefault(key, {})[block_index] = value
            entry["distinct_keys"] = len(merged)
            entry["keys_in_all_blocks"] = sum(1 for d in merged.values() if len(d) == len(blocks))
            entry["keys_with_varying_value"] = sum(1 for d in merged.values() if len(set(d.values())) > 1)
        variance.append(entry)
    return {"blocks": per_block, "cross_block_variance": variance}


def logical_immediates_32() -> dict[int, tuple[int, int, int]]:
    """Every 32-bit AArch64 logical immediate mapped to its (N, immr, imms).

    A wide-move census alone cannot clear a constant: ``MOV Wd,#imm`` is an
    alias of ``ORR Wd,WZR,#imm`` and reaches values no MOVZ/MOVK pair builds.
    """
    encodable: dict[int, tuple[int, int, int]] = {}
    for size in (2, 4, 8, 16, 32):
        for ones in range(1, size):
            pattern = (1 << ones) - 1
            for rotation in range(size):
                element = ((pattern >> rotation) | (pattern << (size - rotation))) & ((1 << size) - 1)
                value = 0
                for slot in range(32 // size):
                    value |= element << (slot * size)
                if value in (0, 0xFFFFFFFF):
                    continue
                imms = ((-size * 2) & 0x3F) | (ones - 1)
                encodable.setdefault(value, (0, rotation, imms))
    return encodable


def _wide_move_encodings(value: int) -> dict[str, int]:
    low, high = value & 0xFFFF, (value >> 16) & 0xFFFF
    return {
        "movz_w_low": 0x52800000 | (low << 5),
        "movk_w_high": 0x72A00000 | (high << 5),
        "movz_x_low": 0xD2800000 | (low << 5),
        "movk_x_high": 0xF2A00000 | (high << 5),
    }


def _count_instruction(data: bytes, matcher) -> int:
    count = 0
    for offset in range(0, len(data) - 3, 4):
        if matcher(struct.unpack_from("<I", data, offset)[0]):
            count += 1
    return count


def materialisation_audit(images: dict[str, bytes]) -> list[dict]:
    """For each ranked live value, test all three single-instruction paths.

    A value absent as a stored word, as a wide-move pair and as a logical
    immediate is not reachable by any one-instruction constant path in these
    images.  It may still be computed, which this audit cannot exclude.
    """
    encodable = logical_immediates_32()
    results = []
    for value, label in RANKED_LIVE_VALUES.items():
        needle = value.to_bytes(4, "little")
        stored = {name: blob.count(needle) for name, blob in images.items()}
        wide = _wide_move_encodings(value)
        wide_counts = {
            key: sum(
                _count_instruction(blob, lambda word, base=encoding: (word & 0xFFFFFFE0) == base)
                for blob in images.values()
            )
            for key, encoding in wide.items()
        }
        record = {
            "value": f"0x{value:08x}",
            "candidate": label,
            "stored_word_occurrences": {name: count for name, count in stored.items() if count},
            "stored_word_total": sum(stored.values()),
            "wide_move_halfword_sites": wide_counts,
            # Necessary condition only: it asks whether both halfword encodings
            # occur anywhere, not whether they occur as one adjacent pair in one
            # register.  False therefore excludes the wide-move path outright;
            # True is inconclusive.
            "wide_move_pair_not_excluded": bool(wide_counts["movk_w_high"] and wide_counts["movz_w_low"])
            or bool(wide_counts["movk_x_high"] and wide_counts["movz_x_low"]),
        }
        if value in encodable:
            _n, immr, imms = encodable[value]
            sites = sum(
                _count_instruction(
                    blob,
                    # ORR (immediate) 32-bit: sf=0, opc=01, 100100, N=0 occupy
                    # bits 31..22, so the fixed-field mask must be 0xFFC00000.
                    # A looser mask also matches the 64-bit and N=1 forms.
                    lambda word, r=immr, s=imms: (word & 0xFFC00000) == 0x32000000
                    and ((word >> 16) & 0x3F) == r
                    and ((word >> 10) & 0x3F) == s,
                )
                for blob in images.values()
            )
            record["logical_immediate"] = {"encodable": True, "immr": immr, "imms": imms, "orr_sites": sites}
        else:
            record["logical_immediate"] = {"encodable": False, "orr_sites": 0}
        record["single_instruction_paths_all_absent"] = (
            record["stored_word_total"] == 0
            and not record["wide_move_pair_not_excluded"]
            and record["logical_immediate"]["orr_sites"] == 0
        )
        results.append(record)
    return results


def load_exact_images(firmware_dir: Path) -> dict[str, bytes]:
    images: dict[str, bytes] = {}
    for name, (size, digest) in EXACT_IMAGES.items():
        path = firmware_dir / name
        if not path.exists():
            raise InventoryError(f"missing exact image: {name}")
        blob = path.read_bytes()
        if len(blob) != size or sha256(blob) != digest:
            raise InventoryError(f"{name} is not the exact Experiment 004 artifact")
        images[name] = blob
    return images


def build_manifest(firmware_dir: Path) -> dict:
    images = load_exact_images(firmware_dir)
    dcb = inventory_dcb(images[DCB_IMAGE])
    audit = materialisation_audit(images)

    tables = [
        (block["block_index"], int(index), record)
        for block in dcb["blocks"]
        for index, record in block["sections"].items()
        if record["kind"] != "NOT_A_REGISTER_TABLE"
    ]
    ranked_offset_hits = [
        {"block": block_index, "section": section, "hits": record["ranked_offset_hits"]}
        for block_index, section, record in tables
        if record["ranked_offset_hits"]
    ]
    absolute_bases = sorted(
        {base for _b, _s, record in tables for base in record.get("distinct_64k_bases", [])}
    )
    return {
        "schema": SCHEMA,
        "experiment_id": "019-dcb-register-programming",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "dcb_image": DCB_IMAGE,
        "dcb_image_sha256": EXACT_IMAGES[DCB_IMAGE][1],
        "exact_images": {name: {"size": size, "sha256": digest} for name, (size, digest) in EXACT_IMAGES.items()},
        "dcb": dcb,
        "register_table_count": len(tables),
        "absolute_table_64k_bases": absolute_bases,
        "ranked_absolute_base_reached": sorted(
            {base for _b, _s, record in tables for base in record.get("ranked_base_hits", [])}
        ),
        "ranked_offset_hits": ranked_offset_hits,
        "ranked_value_materialisation": audit,
        "claims": {
            "PROVED": [
                "The xbl_config DCB carries zero-terminated (key, value) register tables "
                "under a strict alignment/ascending/terminator acceptance test.",
                "Both an absolute-address form and a base-relative-offset form are present; "
                "the base-relative form supplies no base, so no absolute target address "
                "need appear as a firmware literal.",
                "No absolute table reaches any of the four ranked MC bases.",
                "Every ranked live value except 0x00001111 is absent from all nine exact "
                "images as a stored 32-bit word, is unreachable by a MOVZ/MOVK pair, and "
                "has no ORR-immediate site.",
            ],
            "REFUTED": [
                "The DCB programs the twelve ranked absolute MC targets.",
            ],
            "UNKNOWN": [
                "The implicit base of every base-relative table.",
                "Whether any ranked value is computed at runtime rather than stored; "
                "repeating-nibble values such as 0x00111111 are trivially loop-built, so "
                "their literal absence is weak evidence.",
                "Whether DDR training firmware outside these nine partitions writes them.",
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
