#!/usr/bin/env python3
"""Reproduce the bounded static semantic claims for Experiment 029A.

This audit consumes the exact captured ABL image and invokes the existing
in-memory UEFI extractor.  It searches only the decompressed GUID-defined
payloads, which are the canonical searchable bytes; the PE32 module bytes are
reported by hash but are not counted a second time because they are contained
in that payload.  The negative is deliberately narrow: exact stored
controller-base literals, exact stored row-space literals, and the tested
three-word spanning-triple encoding.  It does not disassemble the modules or
infer runtime participation.

Host-only and read-only.  No device, transport, firmware state, or live
device-tree input is accessed.
"""
from __future__ import annotations

from array import array
import hashlib
import json
import os
from pathlib import Path
import sys
from collections.abc import Mapping

try:
    from tools import abl_uefi_extract as extractor
    from tools import a90_bank_relation_encoding_audit as relation_audit
except ModuleNotFoundError as error:
    # ``python tools/a90_abl_semantic_audit.py`` puts only ``tools/`` on
    # sys.path.  Add the repository root for the documented direct CLI while
    # preserving normal package imports and surfacing unrelated import errors.
    if error.name != "tools":
        raise
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tools import abl_uefi_extract as extractor
    from tools import a90_bank_relation_encoding_audit as relation_audit


SCHEMA = "a90-abl-semantic-audit-v1"
EXPERIMENT_ID = "029A-abl-semantic-audit"

# The controller bases are the exact constants named by Experiment 029A.  They
# are searched as four-byte little-endian literals at every byte offset.
CONTROLLER_BASES = {
    "qhs_mc": (0x09260000, 0x092E0000, 0x09360000, 0x093E0000),
    "qhs_mccc": (0x09250000,),
    "qhs_mccc_master": (0x090B0000,),
}

# Experiment 023R's validated allocation-offset/model bank relation. The seven
# nonzero XOR covectors are the basis-independent numeric row-space target set;
# physical bank-row attribution remains SUPPORTED_WITHIN_MODEL.
BANK_ROWS = (0x009D2000, 0x01A74000, 0x014E8000)
RELATION_BITS = tuple(range(13, 25))
RELATION_MANIFEST_PATH = relation_audit.RELATION_MANIFEST_PATH
CAPTURE_MANIFEST_NAME = "004-live-firmware-readonly-20260825-01.manifest.json"
CAPTURE_MANIFEST_SHA256 = (
    "1ed4b8b14b2e0ccf2d4ae084ea413e0395d9dc488dd5d2bb1dd872fbe20d9247"
)

# These are names and diagnostics that the README attributes to ABL's DDR
# Info/property-consumer path.  They are counted as ASCII substrings in the
# decompressed payload, not interpreted as proof of execution.
DDR_STRINGS = (
    ("error_getting_ddr_info",
     "Error getting DDR Info, Plz check SMEM version (see EFISmem.h)"),
    ("unable_to_get_ddr_info_protocol",
     "INFO: Unable to get DDR Info protocol:%r"),
    ("ddr_header_revision",
     "DDR Header Revision =0x%x"),
    ("ddr_device_type", "ddr_device_type"),
    ("ddr_device_rank_channel", "ddr_device_rank_ch%d"),
    ("ddr_device_hbb_channel_rank", "ddr_device_hbb_ch%d_rank%d"),
    ("ddr_rank_hbb_not_supported",
     "ddr_device_rank, HBB not supported in Revision=0x%x"),
)


def row_space(rows: tuple[int, ...] = BANK_ROWS) -> list[int]:
    """Return the sorted nonzero XOR span of ``rows``."""
    values: set[int] = set()
    for selector in range(1, 1 << len(rows)):
        value = 0
        for index, row in enumerate(rows):
            if selector & (1 << index):
                value ^= row
        values.add(value)
    return sorted(values)


def find_all(data: bytes, needle: bytes) -> list[int]:
    """Find every occurrence, including unaligned and overlapping offsets."""
    if not needle:
        raise ValueError("empty needles are not meaningful")
    offsets: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


def _hex32(value: int) -> str:
    return f"0x{value:08x}"


def _aggregate_sha256(targets: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(targets):
        digest.update(targets[name])
    return digest.hexdigest()


def _literal_counts(targets: Mapping[str, bytes], values: tuple[int, ...]) -> dict:
    """Count exact u32 little-endian values in every canonical target."""
    records = []
    for value in sorted(values):
        needle = value.to_bytes(4, "little")
        per_target = {
            name: len(find_all(targets[name], needle))
            for name in sorted(targets)
        }
        records.append({
            "value": _hex32(value),
            "width_bytes": 4,
            "byte_order": "little",
            "offset_policy": "every_byte_offset",
            "count": sum(per_target.values()),
            "per_target": per_target,
        })
    return {
        "encoding": "exact_u32_little_endian",
        "offset_policy": "every_byte_offset",
        "values": records,
        "total_count": sum(record["count"] for record in records),
    }


def _span_of_three(a: int, b: int, c: int) -> int:
    span = {0}
    for value in (a, b, c):
        prior = tuple(span)
        span.update(other ^ value for other in prior)
    return len(span)


def adjacent_triple_audit(
    targets: Mapping[str, bytes],
    masks: list[int],
    max_shift: int = 20,
    strides: tuple[int, ...] = (4, 8),
) -> list[dict]:
    """Find the tested three-word encoding that spans all seven covectors.

    A compact native-endian array is used for the word view and byte-swapped
    on non-little-endian hosts.  This avoids the much larger tuple produced by
    unpacking the complete multi-megabyte payload while retaining a stable
    little-endian interpretation.
    """
    packed = [mask >> RELATION_BITS[0] for mask in masks]
    matches: list[dict] = []
    for name in sorted(targets):
        data = targets[name]
        word_count = len(data) // 4
        if word_count < 3:
            continue
        words = array("I")
        words.frombytes(data[:word_count * 4])
        if sys.byteorder != "little":
            words.byteswap()
        for shift in range(max_shift + 1):
            shifted = {value << shift for value in packed}
            if max(shifted, default=0) >> 32:
                continue
            for stride in strides:
                if stride <= 0 or stride % 4:
                    raise ValueError("triple stride must be a positive word multiple")
                step = stride // 4
                if step <= 0:
                    raise ValueError("triple stride must advance")
                for index in range(0, word_count - 2 * step):
                    a = words[index]
                    b = words[index + step]
                    c = words[index + 2 * step]
                    if not (a and b and c):
                        continue
                    if a in shifted and b in shifted and c in shifted:
                        if _span_of_three(a, b, c) == 8:
                            matches.append({
                                "target": name,
                                "file_offset": f"0x{index * 4:x}",
                                "stride": stride,
                                "shift": shift,
                                "words": [f"0x{a:08x}", f"0x{b:08x}",
                                          f"0x{c:08x}"],
                            })
    return matches


def _named_string_counts(targets: Mapping[str, bytes]) -> dict:
    result = {}
    for key, text in DDR_STRINGS:
        needle = text.encode("ascii")
        per_target = {
            name: len(find_all(targets[name], needle))
            for name in sorted(targets)
        }
        result[key] = {
            "text": text,
            "count": sum(per_target.values()),
            "per_target": per_target,
        }
    return result


def analyse_targets(
    targets: Mapping[str, bytes],
    relation_manifest: str | Path = RELATION_MANIFEST_PATH,
) -> dict:
    """Run the deterministic semantic searches over canonical byte targets."""
    if not targets:
        raise ValueError("at least one decompressed target is required")
    relation_dependency = relation_audit.validate_relation_manifest(relation_manifest)
    ordered = {name: targets[name] for name in sorted(targets)}
    masks = row_space()
    base_sets = {
        name: _literal_counts(ordered, values)
        for name, values in CONTROLLER_BASES.items()
    }
    row_literals = _literal_counts(ordered, tuple(masks))
    triples = adjacent_triple_audit(ordered, masks)
    return {
        "search_scope": {
            "kind": "decompressed_guid_defined_payloads",
            "target_count": len(ordered),
            "targets": [
                {
                    "name": name,
                    "bytes": len(ordered[name]),
                    "sha256": hashlib.sha256(ordered[name]).hexdigest(),
                }
                for name in sorted(ordered)
            ],
            "total_bytes": sum(len(data) for data in ordered.values()),
            "aggregate_sha256": _aggregate_sha256(ordered),
            "module_overlap_policy": (
                "PE32 modules are reported by hash but are not counted again; "
                "they are contained in the decompressed payload."
            ),
        },
        "controller_base_literals": {
            "scope": "all canonical decompressed payloads",
            "sets": base_sets,
            "total_count": sum(record["total_count"]
                                for record in base_sets.values()),
        },
        "bank_row_space_literals": {
            "rows": [_hex32(value) for value in BANK_ROWS],
            "row_space": [_hex32(value) for value in masks],
            "coordinate_scope": "allocation-offset/model coordinates",
            "physical_attribution": {
                "classification": "SUPPORTED_WITHIN_MODEL",
                "reason": (
                    "Numeric-mask spans and search counts are proved only in "
                    "allocation-offset/model coordinates; physical bank-row "
                    "attribution inherits the validated 023R model assumptions."
                ),
            },
            "scope": "all canonical decompressed payloads",
            **row_literals,
        },
        "adjacent_triples": {
            "scope": "all canonical decompressed payloads",
            "relation_bits": [f"PA{bit}" for bit in RELATION_BITS],
            "max_shift": 20,
            "strides_bytes": [4, 8],
            "matches": triples,
            "count": len(triples),
        },
        "named_ddr_strings": {
            "scope": "all canonical decompressed payloads",
            "encoding": "ASCII exact substring",
            "strings": _named_string_counts(ordered),
        },
        "relation_dependency": relation_dependency,
    }


def _walk_volume_hashes(data: bytes, blobs: Mapping[str, bytes]) -> list[dict]:
    """Walk extractor volume nesting and add hashes without decoding twice."""
    segments = extractor.elf32_loads(data)
    payload_segment = max(segments, key=lambda segment: segment["file_size"])
    payload = data[payload_segment["file_offset"]:
                   payload_segment["file_offset"] + payload_segment["file_size"]]
    records: list[dict] = []

    def walk_volume(buf: bytes, origin: str, depth: int) -> None:
        if depth > 8:
            raise extractor.ExtractError("volume nesting exceeded 8")
        header = extractor.parse_fv_header(buf)
        length = header["length"]
        if length > len(buf):
            raise extractor.ExtractError("volume length exceeds available bytes")
        raw = buf[:length]
        records.append({
            "origin": origin,
            "depth": depth,
            "bytes": len(raw),
            "length": length,
            "header_length": header["header_length"],
            "revision": header["revision"],
            "file_system_guid": header["file_system_guid"],
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        for offset, _file_type, _attributes, _header_size, body, _name in \
                extractor.iter_files(raw, header["header_length"]):
            for _section_offset, section_type, section in extractor.iter_sections(body):
                if section_type == 0x02:
                    key = f"{origin}/file@0x{offset:x}/lzma"
                    out = blobs.get(key)
                    if out is not None:
                        walk_sections_for_volumes(
                            out, key, depth + 1)
                elif section_type == 0x17:
                    walk_volume(section[4:],
                                f"{origin}/file@0x{offset:x}/fv",
                                depth + 1)

    def walk_sections_for_volumes(buf: bytes, origin: str, depth: int) -> None:
        for offset, section_type, section in extractor.iter_sections(buf):
            if section_type == 0x17:
                walk_volume(section[4:], f"{origin}/fv@0x{offset:x}", depth)

    walk_volume(payload, "abl", 0)
    return records


def _claims(semantic: dict) -> dict:
    base_absent = semantic["controller_base_literals"]["total_count"] == 0
    row_absent = semantic["bank_row_space_literals"]["total_count"] == 0
    triple_absent = semantic["adjacent_triples"]["count"] == 0
    refuted: list[str] = []
    if base_absent:
        refuted.append(
            "In the searched canonical payloads, no listed controller-base "
            "value occurs as an exact stored u32 little-endian literal."
        )
    if row_absent:
        refuted.append(
            "In the searched canonical payloads, no validated allocation-offset/"
            "model row-space value occurs as an exact stored u32 little-endian literal."
        )
    if triple_absent:
        refuted.append(
            "In the searched canonical payloads, no tested adjacent three-word "
            "encoding spans the validated allocation-offset/model row space."
        )
    supported: list[str] = []
    if not base_absent:
        supported.append("A listed controller-base literal was found in scope; see counts.")
    if not row_absent:
        supported.append("A validated allocation-offset/model row-space literal was found in scope; see counts.")
    if not triple_absent:
        supported.append("A tested spanning triple over the validated allocation-offset/model row space was found in scope; see matches.")
    supported.append(
        "Physical bank-row attribution of the numeric masks and spans is "
        "SUPPORTED_WITHIN_MODEL only under the validated 023R assumptions."
    )
    ddr_total = sum(item["count"]
                    for item in semantic["named_ddr_strings"]["strings"].values())
    proved = [
        "The exact source was extracted into the canonical decompressed payload "
        "scope and produced the published hashes and counts.",
        "The bank row-space search uses the validated 023R relation in "
        "allocation-offset/model coordinates; its numeric search counts are "
        "static results in that scope.",
        f"The named DDR diagnostic/property strings have {ddr_total} total "
        "ASCII occurrences under the recorded per-string counts; this is "
        "static naming evidence only.",
    ]
    return {
        "PROVED": proved,
        "SUPPORTED": supported,
        "REFUTED": refuted,
        "UNKNOWN": [
            "Whether ABL computes a controller base, row-space value, or any "
            "equivalent relation at runtime.",
            "Whether an extracted PE32 module participates in controller "
            "programming or performs a runtime write; the modules were not "
            "disassembled or executed by this audit.",
            "Whether the named DDR strings were reached on the captured boot, "
            "or what DDR Info structure SMEM supplied.",
            "The live device-tree property set and hash: no retained DT payload, "
            "property dump, or DT hash is an input to this audit.",
        ],
        "HYPOTHESIS": [],
    }


def audit_image(data: bytes, source_filename: str = "abl--sdd8.bin",
                tool_sha256: str = "NOT_APPLICABLE",
                extractor_sha256: str = "NOT_APPLICABLE",
                relation_manifest: str | Path = RELATION_MANIFEST_PATH) -> dict:
    """Extract and audit one exact ABL image entirely in memory."""
    extraction = extractor.extract(data)
    roots = {
        name: blob for name, blob in extraction["blobs"].items()
        if name.endswith("/lzma")
    }
    if not roots:
        raise ValueError("extractor produced no decompressed canonical payload")
    semantic = analyse_targets(roots, relation_manifest=relation_manifest)
    volumes = _walk_volume_hashes(data, extraction["blobs"])
    extracted = {
        name: {
            "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
        }
        for name, blob in sorted(extraction["blobs"].items())
    }
    modules = [dict(module) for module in extraction["modules"]]
    result = {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "timestamp": "2026-08-26",
        "target": {
            "model": "SM-A908N",
            "soc": "SM8150",
            "partition": "abl",
            "source_filename": Path(source_filename).name,
        },
        "build": {
            "device_build": "v2321-usb-clean-identity-rodata",
            "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
            "capture_id": "004-live-firmware-readonly-20260825-01",
            "capture_manifest": CAPTURE_MANIFEST_NAME,
            "capture_manifest_sha256": CAPTURE_MANIFEST_SHA256,
        },
        "source_image": {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "pt_load": extraction["pt_load"],
        "volumes": volumes,
        "modules": modules,
        "extracted": extracted,
        "extracted_total_bytes": sum(item["bytes"] for item in extracted.values()),
        **semantic,
        "claims": _claims(semantic),
        "claim_boundary": {
            "static_negative": (
                "exact stored u32 literals and the tested adjacent-triple "
                "encoding in canonical decompressed payloads"
            ),
            "runtime_participation": "UNKNOWN",
            "disassembly": "NOT_PERFORMED",
            "live_device_tree": "UNRETAINED_UNKNOWN",
        },
        "host_analysis": {
            "mode": "HOST_ONLY_READ_ONLY",
            "tool": "tools/a90_abl_semantic_audit.py",
            "tool_sha256": tool_sha256,
            "extractor": "tools/abl_uefi_extract.py",
            "extractor_sha256": extractor_sha256,
            "extraction_in_memory": True,
            "semantic_repetitions": 1,
        },
        "commands": [
            "host: python3 tools/abl_uefi_extract.py --image <private abl image> --dump-dir <scratch> --output <extraction manifest>",
            "host: python3 tools/a90_abl_semantic_audit.py --image <private abl image> --relation-manifest <023R public manifest> --output <semantic manifest>",
            "host: python3 -m unittest -v tests.test_a90_abl_semantic_audit",
        ],
        "definition_of_done": {
            "commands": {
                "status": "REDACTED_REPRODUCTION_TEMPLATE",
                "command": (
                    "python3 tools/a90_abl_semantic_audit.py --image "
                    "<private abl image> --relation-manifest "
                    "<023R public manifest> --output <semantic manifest>"
                ),
                "reason": (
                    "Private input and output paths are redacted; the exact "
                    "relation manifest is pinned by dependency provenance. "
                    "This template is not an executed-command receipt."
                ),
            },
        },
        "repetitions": 1,
        "device_binding": {
            "status": "NOT_APPLICABLE",
            "reason": "The audit reads an already captured image and never contacts or identifies a live device.",
        },
        "rollback": {
            "status": "NOT_APPLICABLE",
            "reason": "The audit changes no device, firmware, boot, or persistent state.",
        },
        "recovery": {
            "status": "NOT_APPLICABLE",
            "reason": "No device mutation or boot transition occurs in this host-only audit.",
        },
        "live_device_tree": {
            "status": "UNRETAINED_UNKNOWN",
            "retained_evidence": False,
            "property_observation": "UNKNOWN",
            "sha256": "UNKNOWN",
            "reason": "No retained public or private DT payload, property dump, or DT hash is supplied to this audit.",
        },
        "public_private_separation": {
            "public": "Hashes, sizes, structure, counts, strings, classifications, and bounded metadata only.",
            "private": "The captured firmware image and extracted blobs remain private.",
            "raw_bytes_in_manifest": False,
            "private_absolute_paths_in_manifest": False,
        },
    }
    return result


def main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True,
                        help="private captured ABL image")
    parser.add_argument(
        "--relation-manifest", default=str(RELATION_MANIFEST_PATH),
        help="public 023R relation manifest to validate and pin",
    )
    parser.add_argument("--output", required=True, help="public manifest path")
    args = parser.parse_args(argv)

    image_path = Path(args.image)
    data = image_path.read_bytes()
    tool_hash = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
    extractor_hash = hashlib.sha256(
        Path(extractor.__file__).resolve().read_bytes()
    ).hexdigest()
    result = audit_image(data, source_filename=image_path.name,
                         tool_sha256=tool_hash,
                         extractor_sha256=extractor_hash,
                         relation_manifest=args.relation_manifest)
    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(result, indent=1, sort_keys=True) + "\n"
    )
    os.chmod(output_path, 0o644)
    print(json.dumps({
        "source_sha256": result["source_image"]["sha256"],
        "canonical_targets": result["search_scope"]["target_count"],
        "controller_base_literals": result["controller_base_literals"]["total_count"],
        "bank_row_space_literals": result["bank_row_space_literals"]["total_count"],
        "adjacent_triples": result["adjacent_triples"]["count"],
        "live_device_tree": result["live_device_tree"]["status"],
    }, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
