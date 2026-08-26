#!/usr/bin/env python3
"""Audit exact A90 firmware and live registers for validated model-coordinate bank masks.

Experiment 014 recovered a three-row GF(2) bank model and
`tools/a90_bank_hash_literal_audit.py` searched firmware for it.  That audit
had two defects that this one repairs.

Its target was wrong. It searched the row space of the Experiment 014 model
basis, which omitted model bit 24. Experiment 023R resolved the allocation-
offset/model-bit-24 contribution and pinned the kernel uniquely, and the
corrected model row space shares only three of its seven covectors with the set
that audit used: four of its seven targets were values the relation never had,
and four real ones were never searched.

Its negative had no scale.  A 24-bit mask with six to eight set bits occurs in
megabytes of firmware by chance, so "no hit" and "some hits" are both
uninformative without knowing the rate.  This audit measures that rate from
decoy masks drawn with the same popcount profile and reports observed hits
against it.

Why the model-coordinate row space is the right target. A conflict measurement determines
`ker f`, and 168 bases in `GL(3,2)` describe the same kernel.  Its annihilator
-- the row space -- is basis-independent, so its seven nonzero covectors are
the complete target set, and no separate search per basis is needed.

Four encoding families are tested: a stored 32-bit mask literal, a mask held in
a register under any bit alignment with or without an enable bit, a list of bit
indices packed into fixed-width fields, and three adjacent words that together
span the row space.  Host-only; it never contacts the device.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import struct

SCHEMA = "a90-bank-relation-encoding-audit-v1"
EXPERIMENT_ID = "028-bank-relation-encoding-audit"

# These are observations from the retained Verification-012 register set, not
# an inventory of the controller.  Keep the scope attached to the negative so
# a zero match cannot be read as a global absence claim.
OBSERVED_REGISTER_COUNT = 494
OBSERVED_NONZERO_REGISTER_COUNT = 274
OBSERVED_SPAN_WORD_SLOTS = 9305
OBSERVED_SPAN_ADDRESS_COUNT_PER_INSTANCE = 42
OBSERVED_SPAN_DENSITY_PERCENT = 0.4514

#: Experiment 023R's allocation-offset/model relation. Model bit 24 contributes
#: 0b110, so it joins b1 and b2; physical attribution remains model-conditional.
BANK_ROWS = (0x009D2000, 0x01A74000, 0x014E8000)

#: The rows Experiment 014 gave and the earlier audit searched, without PA24.
LEGACY_BANK_ROWS = (0x009D2000, 0x00A74000, 0x004E8000)

RELATION_BITS = tuple(range(13, 25))
RELATION_MANIFEST_NAME = (
    "023R-repaired-region-bank-relation-20260826-01.manifest.json"
)
RELATION_MANIFEST_PATH = (
    Path(__file__).resolve().parents[1] / "evidence" / "manifests" /
    RELATION_MANIFEST_NAME
)
RELATION_MANIFEST_SHA256 = (
    "5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e"
)


def _manifest_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_relation_manifest(path: str | Path = RELATION_MANIFEST_PATH) -> dict:
    """Validate the exact 023R result before reusing its copied row constants."""
    manifest_path = Path(path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_digest = _manifest_digest(manifest_path)
    if manifest_digest != RELATION_MANIFEST_SHA256:
        raise ValueError(
            "relation dependency hash mismatch: "
            f"{manifest_digest} != {RELATION_MANIFEST_SHA256}"
        )
    if document.get("experiment_id") != "023R-repaired-region-bank-relation":
        raise ValueError("relation dependency has the wrong experiment_id")
    new_bit = document.get("new_bit") or {}
    if new_bit.get("new_bit") != 24 or new_bit.get("contribution") != "0b110":
        raise ValueError("relation dependency does not pin PA24 contribution 0b110")
    rank = document.get("rank") or {}
    if rank.get("rank") != 3 or rank.get("resolved") is not True:
        raise ValueError("relation dependency does not resolve model rank 3")
    kernel = document.get("kernel") or {}
    if kernel.get("coordinate_scope") != "allocation-offset/model coordinates":
        raise ValueError("relation dependency kernel lacks model-coordinate scope")
    if new_bit.get("coordinate_scope") != "allocation-offset/model coordinates":
        raise ValueError("relation dependency PA24 result lacks model-coordinate scope")
    if new_bit.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL":
        raise ValueError("relation dependency PA24 result lacks physical model classification")
    if rank.get("coordinate_scope") != "allocation-offset/model coordinates":
        raise ValueError("relation dependency rank lacks model-coordinate scope")
    if rank.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL":
        raise ValueError("relation dependency rank lacks physical model classification")
    if kernel.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL":
        raise ValueError("relation dependency kernel lacks physical model classification")
    coordinate_scope = document.get("coordinate_scope") or {}
    required_scopes = (
        "measurement_separation", "allocation_offset_algebra",
        "pa24_contribution", "kernel", "rank",
    )
    if any(coordinate_scope.get(key) != "allocation-offset/model coordinates"
           for key in required_scopes):
        raise ValueError("relation dependency lacks allocation-offset/model scope")
    if coordinate_scope.get("physical_mapping") != "SUPPORTED_WITHIN_MODEL":
        raise ValueError("relation dependency lacks physical model classification")
    physical = document.get("physical_provenance") or {}
    if physical.get("classification") != "SUPPORTED_WITHIN_MODEL":
        raise ValueError("relation dependency lacks SUPPORTED_WITHIN_MODEL physical classification")
    if physical.get("pagemap_status") != "BLIND":
        raise ValueError("relation dependency pagemap is not BLIND")
    pagemap = (document.get("pa_provenance") or {}).get("pagemap", [])
    if not pagemap or any(record.get("status") != "BLIND" or
                           record.get("effective_contiguity") != "UNKNOWN"
                           for record in pagemap):
        raise ValueError("relation dependency pagemap records are not normalized BLIND")
    return {
        "experiment_id": document["experiment_id"],
        "manifest": manifest_path.name,
        "sha256": manifest_digest,
        "new_bit": 24,
        "contribution": "0b110",
        "rank": 3,
        "coordinate_scope": "allocation-offset/model coordinates",
        "physical_classification": "SUPPORTED_WITHIN_MODEL",
        "validated": True,
    }


def validate_source_manifest(path: str | Path, targets: dict[str, bytes]) -> dict:
    """Check scratch blobs against the exact extractor ``extracted`` records."""
    manifest_path = Path(path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("experiment_id") != "029A-abl-uefi-searchability":
        raise ValueError("source manifest is not the 029A extraction manifest")
    extracted = document.get("extracted")
    if not isinstance(extracted, dict) or not extracted:
        raise ValueError("source manifest has no extracted records")
    expected: dict[str, dict] = {}
    for logical_name, record in extracted.items():
        dump_name = record.get("dump_name")
        if not dump_name:
            raise ValueError(f"source manifest record lacks dump_name: {logical_name}")
        if dump_name in expected:
            raise ValueError(f"duplicate source dump_name: {dump_name}")
        expected[dump_name] = {
            "bytes": int(record["bytes"]),
            "sha256": str(record["sha256"]),
            "logical_name": logical_name,
        }
    actual = {
        name: {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for name, data in sorted(targets.items())
    }
    if set(actual) != set(expected):
        raise ValueError(
            "source manifest target names differ: "
            f"expected {sorted(expected)}, got {sorted(actual)}"
        )
    for name in sorted(expected):
        if (actual[name]["bytes"] != expected[name]["bytes"] or
                actual[name]["sha256"] != expected[name]["sha256"]):
            raise ValueError(f"source manifest target mismatch: {name}")
    return {
        "experiment_id": document.get("experiment_id"),
        "manifest": manifest_path.name,
        "sha256": _manifest_digest(manifest_path),
        "schema": document.get("schema"),
        "extracted_count": len(expected),
        "validated": True,
    }


def row_space(rows: tuple[int, ...]) -> list[int]:
    """The nonzero covectors spanned by the rows.

    This is the annihilator of the kernel and does not depend on which basis
    of the kernel was written down, so it is the complete search target.
    """
    values = set()
    for selector in range(1, 1 << len(rows)):
        value = 0
        for index, row in enumerate(rows):
            if (selector >> index) & 1:
                value ^= row
        values.add(value)
    return sorted(values)


def find_all(data: bytes, needle: bytes) -> list[int]:
    result, start = [], 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return result
        result.append(offset)
        start = offset + 1


def literal_audit(targets: dict[str, bytes], masks: list[int],
                  width: int = 4) -> list[dict]:
    """Every occurrence of a mask as a little-endian literal.

    Alignment is recorded rather than filtered: a 24-bit mask landing one byte
    into a 64-bit address-table entry is a coincidence with a signature, and
    dropping it silently would hide how the hit arose.
    """
    hits = []
    for name in sorted(targets):
        data = targets[name]
        for mask in masks:
            if mask >> (8 * width):
                continue
            for offset in find_all(data, mask.to_bytes(width, "little")):
                hits.append({
                    "target": name,
                    "mask": f"0x{mask:08x}",
                    "file_offset": f"0x{offset:x}",
                    "aligned_u32": offset % 4 == 0,
                })
    return hits


def chance_baseline(targets: dict[str, bytes], masks: list[int],
                    trials: int = 200, seed: int = 0xA90) -> dict:
    """How often does a mask like these occur by chance?

    Decoys are drawn over the same address bits with the same popcount
    profile as the real covectors, so the comparison isolates whether the
    relation is present rather than whether masks of this shape are common.
    """
    rng = random.Random(seed)
    popcounts = [bin(mask).count("1") for mask in masks]
    real = set(masks)
    decoys = []
    while len(decoys) < trials:
        chosen = rng.sample(RELATION_BITS, rng.choice(popcounts))
        value = sum(1 << bit for bit in chosen)
        if value not in real:
            decoys.append(value)
    hits = literal_audit(targets, decoys)
    return {
        "trials": trials,
        "decoy_hits": len(hits),
        "hits_per_mask": len(hits) / trials,
        "expected_for_real_masks": len(hits) / trials * len(masks),
    }


def register_audit(registers: list[dict], masks: list[int],
                   max_shift: int = 20) -> list[dict]:
    """Registers whose value is a covector under some bit alignment.

    The mask is packed down to the relation's own bits first, then shifted, so
    an encoding that starts the mask at any register bit is covered.  An
    enable bit in position 0, as AMD's US10403333B2 uses, is tested too.
    """
    packed = {mask >> RELATION_BITS[0]: mask for mask in masks}
    matches = []
    for entry in registers:
        value = int(entry["value"], 16)
        if value == 0:
            continue
        for small, mask in packed.items():
            for shift in range(max_shift + 1):
                if value == small << shift:
                    form = "plain"
                elif value == ((small << (shift + 1)) | 1):
                    form = "enable_bit"
                else:
                    continue
                matches.append({
                    "register": entry["register"],
                    "topology": entry.get("topology", []),
                    "value": entry["value"],
                    "mask": f"0x{mask:08x}",
                    "shift": shift,
                    "form": form,
                })
    return matches


def index_encoding_audit(registers: list[dict], masks: list[int],
                         widths: tuple[int, ...] = (4, 5, 6, 8),
                         bases: tuple[int, ...] = (0, 9, 13)) -> list[dict]:
    """Registers whose value lists the relation's bits as packed indices.

    Several observed controller values are structured as repeating nibbles,
    which is what a table of field indices looks like rather than a bitmask,
    so that encoding family is tested rather than assumed away.

    A zero field is ambiguous: it can mean an unused slot or the index zero
    itself.  Both readings are tested, because dropping zeros would make any
    relation containing the base bit unrepresentable and turn a blind spot
    into a false negative.
    """
    wanted = {frozenset(b for b in RELATION_BITS if (mask >> b) & 1): mask
              for mask in masks}
    matches = []
    for entry in registers:
        value = int(entry["value"], 16)
        if value == 0:
            continue
        for width in widths:
            fields = [(value >> (i * width)) & ((1 << width) - 1)
                      for i in range(32 // width)]
            for base in bases:
                readings = {
                    "zero_is_unused": frozenset(f + base for f in fields if f),
                    "zero_is_index": frozenset(f + base for f in fields),
                }
                for reading, indices in readings.items():
                    mask = wanted.get(indices)
                    if mask is not None:
                        matches.append({
                            "register": entry["register"],
                            "topology": entry.get("topology", []),
                            "value": entry["value"],
                            "mask": f"0x{mask:08x}",
                            "field_width": width,
                            "index_base": base,
                            "zero_field_reading": reading,
                        })
    return matches


def _span_of_three(a: int, b: int, c: int) -> int:
    space = {0}
    for value in (a, b, c):
        space |= {other ^ value for other in space}
    return len(space)


def adjacent_triple_audit(targets: dict[str, bytes], masks: list[int],
                          max_shift: int = 20,
                          strides: tuple[int, ...] = (4, 8)) -> list[dict]:
    """Three nearby words that together span the whole row space.

    A hash block storing one mask per output bit would place three related
    values close together, and three coordinated values are a far stronger
    signature than any single mask: the chance rate that defeats a lone
    literal does not reach three at once.
    """
    packed = [mask >> RELATION_BITS[0] for mask in masks]
    matches = []
    for name in sorted(targets):
        data = targets[name]
        count = len(data) // 4
        if count < 3:
            continue
        words = struct.unpack_from(f"<{count}I", data, 0)
        for shift in range(max_shift + 1):
            shifted = {value << shift for value in packed}
            if max(shifted) >> 32:
                continue
            for stride in strides:
                step = stride // 4
                for index in range(count - 2 * step):
                    a, b, c = words[index], words[index + step], words[index + 2 * step]
                    if not (a and b and c):
                        continue
                    if a in shifted and b in shifted and c in shifted:
                        if _span_of_three(a, b, c) == 8:
                            matches.append({
                                "target": name,
                                "file_offset": f"0x{index * 4:x}",
                                "stride": stride,
                                "shift": shift,
                                "words": [f"0x{a:08x}", f"0x{b:08x}", f"0x{c:08x}"],
                            })
    return matches


def legacy_comparison(legacy_rows: tuple[int, ...],
                      rows: tuple[int, ...]) -> dict:
    """What the earlier audit searched, against what the relation actually is."""
    legacy = set(row_space(legacy_rows))
    current = set(row_space(rows))
    return {
        "legacy_targets": [f"0x{v:08x}" for v in sorted(legacy)],
        "current_targets": [f"0x{v:08x}" for v in sorted(current)],
        "shared": [f"0x{v:08x}" for v in sorted(legacy & current)],
        "legacy_only_never_in_relation": [f"0x{v:08x}" for v in sorted(legacy - current)],
        "current_only_never_searched": [f"0x{v:08x}" for v in sorted(current - legacy)],
    }


def audit(targets: dict[str, bytes], registers: list[dict],
          rows: tuple[int, ...] = BANK_ROWS,
          experiment_id: str = EXPERIMENT_ID,
          relation_manifest: str | Path = RELATION_MANIFEST_PATH,
          source_manifest: str | Path | None = None) -> dict:
    relation_dependency = validate_relation_manifest(relation_manifest)
    source_dependency = (
        validate_source_manifest(source_manifest, targets)
        if source_manifest is not None else None
    )
    masks = row_space(rows)
    literals = literal_audit(targets, masks)
    baseline = chance_baseline(targets, masks)
    register_count = len(registers)
    nonzero_register_count = sum(
        1 for r in registers if int(r["value"], 16) != 0
    )
    exact_register_capture = (
        register_count == OBSERVED_REGISTER_COUNT
        and nonzero_register_count == OBSERVED_NONZERO_REGISTER_COUNT
    )
    observed_span_count = (
        OBSERVED_SPAN_ADDRESS_COUNT_PER_INSTANCE if exact_register_capture else None
    )
    observed_span_slots = OBSERVED_SPAN_WORD_SLOTS if exact_register_capture else None
    observed_span_density = OBSERVED_SPAN_DENSITY_PERCENT if exact_register_capture else None
    full_block_density = 0.2563 if exact_register_capture else None
    register_observation_status = (
        "NOT_APPLICABLE" if register_count == 0 else "OBSERVED_BOUNDED"
    )
    register_supported = [] if register_count == 0 else [
        "The zero register-family matches support a negative over the "
        "observed register set, subject to the stated encoding and span "
        "limits."
    ]
    register_refuted = [] if register_count == 0 else [
        "Over the observed register set only, no decoded controller "
        "register holds a relation covector under the tested encodings; "
        "this is not a global absence claim."
    ]
    register_negative_status = (
        "NOT_APPLICABLE" if register_count == 0 else "OBSERVED_BOUNDED"
    )
    if register_count == 0:
        register_scope_text = (
            "No decoded controller-register input was supplied; register "
            "observation is NOT_APPLICABLE for these targets."
        )
        claim_scope_text = (
            "Register observation and register-family negative claims are "
            "NOT_APPLICABLE because no decoded register input was supplied."
        )
    else:
        register_scope_text = (
            "Verification-012 decoded controller-register set and its "
            "enumerated 9305-word ranked-instance span only; not global "
            "controller coverage."
        )
        claim_scope_text = (
            f"Register negatives are limited to the observed {register_count} decoded "
            f"controller registers ({nonzero_register_count} nonzero) and the "
            f"{observed_span_density if observed_span_density is not None else 'UNKNOWN'} "
            "observed-span density; this is not global absence from the controller."
        )
    numeric_refuted = []
    if not literals:
        numeric_refuted.append(
            "In the searched target bytes, no validated allocation-offset/model "
            "row-space value occurs as "
            "an exact stored u32 little-endian literal."
        )
    triple_matches = adjacent_triple_audit(targets, masks)
    if not triple_matches:
        numeric_refuted.append(
            "In the searched target bytes, no tested adjacent three-word "
            "encoding spans the validated allocation-offset/model row space."
        )
    if source_dependency is not None:
        proved_claims = [
            "The validated 023R relation yields seven numeric covectors in "
            "allocation-offset/model coordinates, and the exact extracted "
            "target hashes produced the recorded bounded numeric-mask counts."
        ]
        unknown_claims = [
            "Whether the relation is represented or used at runtime in the "
            "extracted target remains UNKNOWN; this audit did not disassemble "
            "or execute the target bytes.",
        ]
    else:
        proved_claims = [
            "The corrected numeric row space in allocation-offset/model "
            "coordinates is the complete basis-independent target set for the "
            "validated relation, and the tested firmware/register inputs "
            "produced the recorded family counts.",
        ]
        unknown_claims = [
            f"Whether the relation is stored outside the observed {register_count}-register "
            f"set or outside the {observed_span_density if observed_span_density is not None else 'UNKNOWN'} observed span, whether it is derived "
            "at boot, and the identity of any writer.",
        ]
    if register_count != 0:
        numeric_refuted = register_refuted + numeric_refuted
    supported_claims = [
        "Physical bank-row attribution of the numeric masks and spans is "
        "SUPPORTED_WITHIN_MODEL only under the validated 023R assumptions."
    ] + register_supported
    target_binding = (
        "PROVED_EXACT_EXTRACTED_TARGET_HASHES"
        if source_dependency is not None
        else "PROVED_EXACT_FIRMWARE_AND_RETAINED_REGISTER_INPUT_HASHES"
    )
    build_reason = (
        "NOT_APPLICABLE: host-only static analysis; no live device contact "
        "occurred; exact extracted target hashes were validated against the "
        "source manifest."
        if source_dependency is not None else
        "NOT_APPLICABLE: host-only static analysis; no live device contact "
        "occurred; retained hashed firmware and register artifacts were used"
    )
    if source_dependency is not None:
        command_template = (
            "python3 tools/a90_bank_relation_encoding_audit.py --capture "
            "<scratch> --experiment-id 029A-bank-relation-audit-over-abl "
            "--source-manifest <029A extraction manifest> --relation-manifest "
            "<023R public manifest> --output <029A bank-audit manifest>"
        )
    else:
        command_template = (
            "python3 tools/a90_bank_relation_encoding_audit.py --capture "
            "<capture-dir> --shrm <SHRM_MEM.BIN> --analysis <analysis.json> "
            "--relation-manifest <023R public manifest> --output "
            "<public-manifest-path>"
        )
    return {
        "schema": SCHEMA,
        "experiment_id": experiment_id,
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "rows": [f"0x{row:08x}" for row in rows],
        "row_space": [f"0x{mask:08x}" for mask in masks],
        "relation_dependency": relation_dependency,
        "relation_coordinate_scope": "allocation-offset/model coordinates",
        "physical_attribution": {
            "classification": "SUPPORTED_WITHIN_MODEL",
            "reason": (
                "Numeric-mask spans and search counts are proved only in "
                "allocation-offset/model coordinates; physical bank-row "
                "attribution inherits the validated 023R model assumptions."
            ),
        },
        "source_manifest_dependency": source_dependency,
        "targets": {name: {"bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()}
                    for name, data in sorted(targets.items())},
        "register_count": register_count,
        "nonzero_register_count": nonzero_register_count,
        "register_observation_scope": {
            "status": register_observation_status,
            "negative_claim_status": register_negative_status,
            "observed_register_count": register_count,
            "observed_nonzero_register_count": nonzero_register_count,
            "ranked_instance_observed_address_count": observed_span_count,
            "observed_span_word_slots": observed_span_slots,
            "observed_span_address_density_percent": observed_span_density,
            "full_64k_word_slot_density_percent": full_block_density,
            "scope": register_scope_text,
        },
        "literal": {"hits": literals, "count": len(literals)},
        "chance_baseline": baseline,
        "literal_verdict": (
            "BELOW_CHANCE" if len(literals) <= baseline["expected_for_real_masks"]
            else "ABOVE_CHANCE"),
        "register_mask": register_audit(registers, masks),
        "register_index_encoding": index_encoding_audit(registers, masks),
        "adjacent_triple": triple_matches,
        "legacy_comparison": legacy_comparison(LEGACY_BANK_ROWS, rows),
        "claim_scope": claim_scope_text,
        "claims": {
            "PROVED": proved_claims,
            "SUPPORTED": supported_claims,
            "REFUTED": numeric_refuted,
            "UNKNOWN": unknown_claims,
            "HYPOTHESIS": [],
        },
        "definition_of_done": {
            "target": {
                "binding": target_binding,
                "marketing_name": "A90 5G",
                "model": "SM-A908N",
                "soc": "SM8150",
                "soc_name": "Snapdragon 855",
            },
            "build": {
                "status": "NOT_APPLICABLE",
                "reason": build_reason,
            },
            "timestamp": {
                "status": "NOT_APPLICABLE",
                "reason": "Deterministic host-only publication does not embed a wall-clock timestamp.",
            },
            "commands": {
                "status": "REDACTED_REPRODUCTION_TEMPLATE",
                "command": command_template,
                "reason": (
                    "Private input and output paths are redacted; exact target and "
                    "relation hashes are pinned when dependencies are supplied. "
                    "This template is not an executed-command receipt."
                ),
            },
            "repetitions": {
                "status": "NOT_APPLICABLE",
                "reason": "NOT_APPLICABLE: no live repetitions; only bounded host analysis was run",
            },
            "rollback": {
                "status": "NOT_APPLICABLE",
                "reason": "NOT_APPLICABLE: no device or persistent state was changed",
            },
            "recovery": {
                "status": "NOT_APPLICABLE",
                "reason": "NOT_APPLICABLE: no device, boot, transport, or runtime state was touched",
            },
            "device_binding": {
                "status": "NOT_APPLICABLE",
                "reason": "NOT_APPLICABLE: host-only analysis of retained artifacts; no live device was contacted",
            },
            "tool_and_build": {
                "tool": f"{__file__.split('/')[-1]} schema {SCHEMA}",
                "build": "NOT_APPLICABLE",
                "build_reason": "The host-only analyzer is interpreted Python source and produces no firmware/kernel build output.",
            },
        },
    }


def main(argv: list[str]) -> int:
    import argparse
    import pathlib

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True,
                        help="directory of captured firmware images")
    parser.add_argument("--shrm", help="SHRM_MEM.BIN path")
    parser.add_argument("--analysis",
                        help="decoded-register analysis JSON; omit to audit "
                             "images only")
    parser.add_argument(
        "--relation-manifest", default=str(RELATION_MANIFEST_PATH),
        help="public 023R relation manifest to validate and pin",
    )
    parser.add_argument(
        "--source-manifest",
        help="029A extraction manifest whose extracted records must match capture",
    )
    parser.add_argument("--experiment-id", default=EXPERIMENT_ID,
                        help="published experiment identifier (default: %(default)s)")
    parser.add_argument("--output", required=True, help="manifest path")
    args = parser.parse_args(argv)

    capture = pathlib.Path(args.capture)
    targets = {p.name: p.read_bytes() for p in sorted(capture.glob("*.bin"))}
    if args.shrm:
        shrm = pathlib.Path(args.shrm)
        targets[shrm.name] = shrm.read_bytes()
    registers = []
    if args.analysis:
        analysis = json.loads(pathlib.Path(args.analysis).read_text())
        registers = analysis["decoded_registers"]

    result = audit(
        targets,
        registers,
        experiment_id=args.experiment_id,
        relation_manifest=args.relation_manifest,
        source_manifest=args.source_manifest,
    )
    output_path = pathlib.Path(args.output)
    output_path.write_text(json.dumps(result, indent=1) + "\n")
    os.chmod(output_path, 0o644)
    print(json.dumps({
        "row_space": result["row_space"],
        "literal_hits": result["literal"]["count"],
        "chance": result["chance_baseline"],
        "literal_verdict": result["literal_verdict"],
        "register_mask_matches": len(result["register_mask"]),
        "register_index_matches": len(result["register_index_encoding"]),
        "adjacent_triple_matches": len(result["adjacent_triple"]),
        "legacy_targets_never_in_relation":
            result["legacy_comparison"]["legacy_only_never_in_relation"],
    }, indent=1))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
