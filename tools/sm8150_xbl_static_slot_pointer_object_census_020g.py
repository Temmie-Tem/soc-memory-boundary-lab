#!/usr/bin/env python3
"""Bounded census of pointer/object accesses found by Verification 020F.

The pass consumes the exact public 020F manifest, rechecks its hash, and
re-decodes only the 020F address-use instruction VAs in the exact XBL.  It
labels immediate scalar accesses as object-field-shaped and register-offset
accesses as array-element-shaped.  No static base is promoted to a runtime
pointer, physical address, MMIO aperture, or DRAM coordinate.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.sm8150_xbl_second_caller_field_use_020d import (
    FIRMWARE_DIR,
    Image,
    TraceError,
    decode_ldr_unsigned,
    decode_str_unsigned,
    load_exact,
    write_no_clobber,
)
from tools.sm8150_xbl_static_slot_census_020e import XBL_NAME, XBL_SHA256, XBL_SIZE
from tools.sm8150_xbl_static_slot_load_use_020f import STATIC_SLOT_PAGE, build_manifest as build_020f_manifest


SCHEMA = "sm8150-xbl-static-slot-pointer-object-census-v1"
EXPERIMENT_ID = "020G-static-slot-pointer-object-census"
MODE = "HOST_ONLY_READ_ONLY"
DEPENDENCY_020F_MANIFEST_NAME = "020F-static-slot-load-use-20260827-01.manifest.json"
DEPENDENCY_020F_MANIFEST_SHA256 = "d19687581d046c7b05841aef6340e9a1e3664c69e19903689d1c583aee5b9764"
DEPENDENCY_020F_MANIFEST_PATH = _REPO_ROOT / "evidence/manifests" / DEPENDENCY_020F_MANIFEST_NAME
WINDOW_INSTRUCTIONS = 16


def _load_public_manifest_pin() -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(DEPENDENCY_020F_MANIFEST_PATH, flags)
    except OSError as exc:
        raise TraceError(f"cannot open exact 020F manifest: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise TraceError("020F dependency manifest is not a regular non-empty file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise TraceError("020F dependency manifest truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(fd)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != DEPENDENCY_020F_MANIFEST_SHA256:
        raise TraceError("020F dependency manifest SHA-256 mismatch")
    try:
        manifest = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise TraceError("020F dependency manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != "sm8150-xbl-static-slot-load-use-v1" or manifest.get("classification") != "CLASS C (TRANSFORM ONLY)":
        raise TraceError("020F dependency manifest identity changed")
    return {"filename": DEPENDENCY_020F_MANIFEST_NAME, "size": len(payload), "sha256": digest, "experiment_id": manifest.get("experiment_id")}


def decode_register_offset_memory(word: int) -> tuple[str, int, int, int, int] | None:
    """Decode LDR/STR W/X [Xn,Xm,UXTX] with optional scale."""

    family = word & 0x3FE00C00
    if family not in (0x38600800, 0x38200800) or ((word >> 13) & 0x7) != 0x3:
        return None
    width_code = (word >> 30) & 0x3
    width = 64 if width_code == 0x3 else 32 if width_code == 0x2 else 0
    if not width:
        return None
    return ("LDR" if family == 0x38600800 else "STR", width, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F)


def _event_from_word(image: Image, seed: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    access_va = int(event["va"], 16)
    word = image.word(access_va)
    ldr = decode_ldr_unsigned(word)
    str_decoded = decode_str_unsigned(word)
    immediate = ldr or str_decoded
    if immediate is not None:
        operation = "LDR" if ldr is not None else "STR"
        width, register, base, offset = immediate
        expected_register = event.get("destination") if operation == "LDR" else event.get("source")
        if event["kind"] != "ADDRESS_BASE_USE" or event.get("operation") != operation or event.get("width_bits") != width or event.get("base") != f"X{base}" or int(event.get("offset", "-1"), 16) != offset or expected_register != f"{'W' if width == 32 else 'X'}{register}":
            raise TraceError(f"020F immediate event drift at {event['va']}")
        return {"seed_va": seed["va"], "seed_slot_va": seed["slot_va"], "access_va": event["va"], "kind": operation, "width_bits": width, "base_register": f"X{base}", "field_offset": f"0x{offset:08x}", "register": expected_register, "shape": "IMMEDIATE_OBJECT_FIELD"}
    register_offset = decode_register_offset_memory(word)
    if register_offset is not None:
        operation, width, register, base, index = register_offset
        expected_register = event.get("destination_or_source")
        if event["kind"] != "REGISTER_OFFSET_ADDRESS_USE" or event.get("operation") != operation or event.get("width_bits") != width or f"X{base}" not in event.get("registers", []) or expected_register != f"{'W' if width == 32 else 'X'}{register}":
            raise TraceError(f"020F register-offset event drift at {event['va']}")
        return {"seed_va": seed["va"], "seed_slot_va": seed["slot_va"], "access_va": event["va"], "kind": operation, "width_bits": width, "base_register": f"X{base}", "index_register": f"X{index}", "register": f"{'W' if width == 32 else 'X'}{register}", "shape": "REGISTER_OFFSET_ARRAY_ELEMENT"}
    raise TraceError(f"020F event is not a supported memory form at {event['va']}")


def census_pointer_object(image: Image, dependency_manifest: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    if source["inputs"]["firmware"]["sha256"] != XBL_SHA256 or source["summary"]["seed_load_count"] != 12:
        raise TraceError("020F source identity changed")
    rows: list[dict[str, Any]] = []
    for trace in source["traces"]:
        seed = trace["seed"]
        for event in trace["events"]:
            if event["kind"] in ("ADDRESS_BASE_USE", "REGISTER_OFFSET_ADDRESS_USE"):
                rows.append(_event_from_word(image, seed, event))
    if len(rows) != 12:
        raise TraceError("020F address-use event count changed")
    immediate = [row for row in rows if row["shape"] == "IMMEDIATE_OBJECT_FIELD"]
    register_offset = [row for row in rows if row["shape"] == "REGISTER_OFFSET_ARRAY_ELEMENT"]
    if len(immediate) != 10 or len(register_offset) != 2:
        raise TraceError("020F address-use shape split changed")
    if Counter(row["kind"] for row in immediate) != Counter({"LDR": 7, "STR": 3}):
        raise TraceError("020G immediate LDR/STR split changed")
    if Counter(row["kind"] for row in register_offset) != Counter({"LDR": 2}):
        raise TraceError("020G register-offset operation split changed")
    access_counts = Counter(row["access_va"] for row in rows)
    if len(access_counts) != 11 or sorted(access_counts.values()) != [1] * 10 + [2]:
        raise TraceError("020G unique/duplicate access-VA structure changed")
    duplicate_va = next(access_va for access_va, count in access_counts.items() if count == 2)
    duplicate_rows = [row for row in rows if row["access_va"] == duplicate_va]
    if len({row["seed_slot_va"] for row in duplicate_rows}) != 2:
        raise TraceError("020G duplicate witness is not backed by two distinct seeds")
    unique_accesses = set(access_counts)
    return {"dependency": dependency_manifest, "accesses": rows, "event_count": len(rows), "immediate_object_field_count": len(immediate), "register_offset_array_element_count": len(register_offset), "unique_access_va_count": len(unique_accesses), "duplicate_witness_count": len(rows) - len(unique_accesses), "status": "SUPPORTED_BOUNDED_POINTER_OBJECT_CENSUS"}


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    dependency = _load_public_manifest_pin()
    image = Image(load_exact(firmware_dir / XBL_NAME))
    census = census_pointer_object(image, dependency, build_020f_manifest(firmware_dir))
    return {"schema": SCHEMA, "experiment_id": EXPERIMENT_ID, "mode": MODE, "device_access": "none", "classification": "CLASS C (TRANSFORM ONLY)", "eligibility": "NOT_ELIGIBLE", "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "dependency_020f": dependency}, "census": census, "scope": {"model": "EXACT_020F_ADDRESS_USE_REDECODE", "window_instructions": WINDOW_INSTRUCTIONS, "recognized_forms": ["LDR_STR_UNSIGNED", "LDR_STR_REGISTER_OFFSET_UXTX"], "runtime_base": "UNKNOWN", "physical_to_dram": "UNKNOWN", "mmio_identity": "UNKNOWN", "global_writer_consumer_absence": "UNKNOWN", "never_scan_arbitrary_ranges": True}, "claims": {"PROVED": ["The exact retained A90 XBL and public 020F manifest are bound by size/SHA-256 before analysis.", "The 020F address-use events re-decode to ten immediate scalar object-field-shaped accesses and two register-offset array-element-shaped witnesses, with one duplicate access VA witness."], "SUPPORTED": ["The bounded uses are more consistent with local pointer/object state than with a directly identified controller register, but the runtime base and semantics are unresolved."], "HYPOTHESIS": ["The six static slots may hold pointers to local configuration objects or arrays rather than final DRAM-controller state."], "REFUTED": [], "UNKNOWN": ["Runtime pointer values/currentness/execution, object types and semantics, global writer/consumer absence, MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing and bypass."]}, "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only static pointer/object census; no activation or live state was accessed."}, "definition_of_done": {"target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"}, "build": {"status": "NOT_APPLICABLE", "reason": "Interpreted host Python; no device/kernel build."}, "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."}, "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_static_slot_pointer_object_census_020g.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."}, "repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no runtime repetitions."}, "rollback": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "recovery": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "device_binding": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device contact."}, "tool_and_build": {"tool": f"sm8150_xbl_static_slot_pointer_object_census_020g.py schema {SCHEMA}", "build": "NOT_APPLICABLE"}}}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = (json.dumps(build_manifest(args.firmware_dir), indent=1, sort_keys=True) + "\n").encode()
        publication = write_no_clobber(args.output, payload)
    except (TraceError, OSError) as exc:
        print(f"020G: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
