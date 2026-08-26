#!/usr/bin/env python3
"""Verification 017: can a bank-granular check separate protected memory?

The question this project exists to answer decomposes into two premises.  P1 is
that a mutable address transform sits downstream of the protection check; P2 is
that Normal World can reach the state that changes it.  Known remapper and
controller apertures have no HLOS grant in the retained TZ policy and one
fixed EL1 load failed, while dynamic and indirect routes remain `UNKNOWN`.  P1
has always had an unexamined half: *where the check sits relative to the
transform* has been `UNKNOWN` since Experiment 008, and no experiment proposed
a way at it, because observing enforcement ordering in the data path needs
either a controller write or a protected read.

There is one thing about the ordering that can be settled without either, and it
follows from the recovered relation rather than from any new measurement.

The argument
-----------
Experiment 023R recovered a rank-3 GF(2) bank-selection relation, and
Verification 016 extended it to PA27 with the rank unchanged.  Rank 3 means
eight bank classes.  The lowest address bit carrying a contribution is PA13, so
the minimum class-change span is 8 KiB, and three independent contributions appear by
PA15, so **a 64-KiB-aligned region of 64 KiB or more covers all eight classes**.
At an arbitrary base the conservative guarantee is **128 KiB**: that width is
certain to contain an aligned 64-KiB sub-block.  A 64-KiB region at an
arbitrary base can cover as few as four classes.

The protected carveouts on this target are megabytes wide.  So is the
unprotected `System RAM` around them.  Both therefore occupy every bank class,
and a check that saw only a bank index could not tell one from the other.

What this settles, and what it does not
---------------------------------------
It refutes one specific shape of enforcement: a check reading only post-decode
*bank* coordinates.  It does not settle the ordering question.  The full DRAM
coordinate — channel, rank, bank, row, column — is a bijection with the physical
address whenever the map is invertible, so a check on the complete post-decode
coordinate carries exactly the same information as a check on the address and
cannot be distinguished this way.  What is excluded is the *narrow* post-decode
check, which is the only one that would have made the transform irrelevant to
enforcement.

That leaves the Skitter premise standing on this platform for the reason it
stands on AMD: enforcement has to retain address information that the DRAM bank
index does not carry, so a mutable map downstream of it would move data under a
check that could not see the move.  This is a structural argument about
granularity, not an observation of the data path, and it is ranked accordingly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
from collections.abc import Mapping, Sequence

SCHEMA = "a90-protection-bank-granularity-v1"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
RELATION_SOURCE = REPO_ROOT / "evidence/manifests/023R-repaired-region-bank-relation-20260826-01.manifest.json"
HIGH_BIT_SOURCE = REPO_ROOT / "evidence/manifests/verification-016-high-bit-relation-20260827-01.manifest.json"
MEMORY_MAP_SOURCE = REPO_ROOT / "docs/MEMORY_MAP.md"
SOURCE_PINS = {
    "relation_manifest": {
        "basename": RELATION_SOURCE.name,
        "size_bytes": 18040,
        "sha256": "5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e",
    },
    "high_bit_manifest": {
        "basename": HIGH_BIT_SOURCE.name,
        "size_bytes": 59504,
        "sha256": "72525cf994e52bbee1c3ed685c49a6ace4049cd7b279cb97811f6a0d3f4f773f",
    },
    "memory_map": {
        "basename": MEMORY_MAP_SOURCE.name,
        "size_bytes": 9428,
        "sha256": "34496c0d92736f7df5b9da69f8bcadfe40fb3ee35558c1b10fab7d06dec86950",
    },
}

PAGE_BYTES = 0x1000

# The relation is only established for these allocation-offset/model bits.  The
# countermodels below deliberately operate on this finite model domain rather
# than pretending that an abstract completion is a physical PA-to-DRAM map.
# The 023R kernel was solved before Verification 016 added PA25..PA27.  Its
# declared model-coordinate domain is therefore bits 13..24 (12 dimensions),
# where a rank-3 relation has a nine-dimensional kernel.  The wider domain is
# retained below for the V016/countermodel projection only.
SOURCE_MODEL_BITS: tuple[int, ...] = tuple(range(13, 25))
SOURCE_MODEL_WIDTH = len(SOURCE_MODEL_BITS)
SOURCE_KERNEL_BASIS_HEX: tuple[str, ...] = (
    "0x100c000", "0x806000", "0x408000", "0x204000", "0x102000",
    "0x8a000", "0x4e000", "0x2c000", "0x16000",
)
MODEL_BITS: tuple[int, ...] = tuple(range(13, 28))
MODEL_WIDTH = len(MODEL_BITS)
BANK_OUTPUT_BITS = 3
DIAGNOSTIC_EXTRA_BITS: tuple[int, ...] = tuple(range(16, 28))
FOLDED_EXTRA_BITS: tuple[int, ...] = tuple(range(16, 27))

#: The rank-3 relation.  PA13..PA23 are Experiment 023R's solved contributions,
#: PA24 is its exhaustively discriminated one, and PA25..PA27 are Verification
#: 016's, each of which duplicates a lower bit's vector rather than adding a
#: dimension.
RELATION: dict[int, int] = {
    13: 0b001, 14: 0b010, 15: 0b100, 16: 0b011, 17: 0b110, 18: 0b111,
    19: 0b101, 20: 0b001, 21: 0b010, 22: 0b100, 23: 0b011, 24: 0b110,
    25: 0b010, 26: 0b101, 27: 0b001,
}

#: Verification 016 determined these by discrimination, independently of the
#: table above.  They must agree with it, and the agreement is checked.
V016_EQUALITIES: dict[int, tuple[int, ...]] = {
    25: (14, 21),
    26: (19,),
    27: (13, 20),
}

#: Carveouts whose live device-tree `reg` is `PROVED` in docs/MEMORY_MAP.md.
PROTECTED_REGIONS: tuple[tuple[str, int, int], ...] = (
    ("hyp_mem",         0x85700000, 0x00600000),
    ("tima_region",     0xB0000000, 0x00200000),
    ("rkp_region",      0xB0200000, 0x00200000),
    ("uh_heap_region",  0xB0400000, 0x01400000),
    ("qseecom_region",  0xA6000000, 0x02400000),
)

#: Raw `/proc/iomem` fragments copied from the pinned MEMORY_MAP source.  This
#: includes the broad resource which contains the RKP and UH heap carveouts.
RAW_SYSTEM_RAM: tuple[tuple[int, int], ...] = (
    (0x80000000, 0x80000FFF),
    (0x80002000, 0x856FFFFF),
    (0x85D00000, 0x85DFFFFF),
    (0x85F40000, 0x85FFFFFF),
    (0x9C400000, 0x9FFFFFFF),
    (0xA8400000, 0xAFFFFFFF),
    (0xB0200000, 0xBCBFFFFF),
    (0xC0000000, 0xC10FFFFF),
    (0xC1300000, 0xC13FFFFF),
    (0xC1C01000, 0x1FFFFFFFF),
)

#: `/proc/iomem` fragments after subtracting the reserved protected ranges that
#: are nested inside one broad System RAM resource and removing the explicit
#: 4-KiB exclusion below.  This is checked against a derivation from
#: `RAW_SYSTEM_RAM`, never treated as an independent source of truth.
SYSTEM_RAM: tuple[tuple[int, int], ...] = (
    (0x80002000, 0x856FFFFF),
    (0x85D00000, 0x85DFFFFF),
    (0x85F40000, 0x85FFFFFF),
    (0x9C400000, 0x9FFFFFFF),
    (0xA8400000, 0xAFFFFFFF),
    (0xB1800000, 0xBCBFFFFF),
    (0xC0000000, 0xC10FFFFF),
    (0xC1300000, 0xC13FFFFF),
    (0xC1C01000, 0x1FFFFFFFF),
)

SYSTEM_RAM_EXCLUDED: tuple[tuple[int, int, str], ...] = (
    (0x80000000, 0x80000FFF, "below_the_64KiB_covering_span"),
)

RESERVED_NESTED_IN_SYSTEM_RAM: tuple[tuple[str, int, int], ...] = (
    ("rkp_region", 0xB0200000, 0x00200000),
    ("uh_heap_region", 0xB0400000, 0x01400000),
)


class GranularityError(RuntimeError):
    pass


def _subtract_inclusive_intervals(
    intervals: Sequence[tuple[int, int]],
    subtractions: Sequence[tuple[int, int]],
) -> tuple[tuple[int, int], ...]:
    """Subtract inclusive intervals without coalescing unrelated resources."""

    current = list(intervals)
    for subtract_start, subtract_end in subtractions:
        if subtract_start < 0 or subtract_end < subtract_start:
            raise GranularityError("invalid interval subtraction")
        next_intervals: list[tuple[int, int]] = []
        for start, end in current:
            if subtract_end < start or end < subtract_start:
                next_intervals.append((start, end))
                continue
            if start < subtract_start:
                next_intervals.append((start, subtract_start - 1))
            if subtract_end < end:
                next_intervals.append((subtract_end + 1, end))
        current = next_intervals
    return tuple(current)


def _derive_system_ram(raw: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    """Derive comparison RAM by subtracting protected/narrow exclusions."""

    nested = tuple((base, base + size - 1) for _, base, size in RESERVED_NESTED_IN_SYSTEM_RAM)
    excluded = tuple((start, end) for start, end, _ in SYSTEM_RAM_EXCLUDED)
    return _subtract_inclusive_intervals(raw, nested + excluded)


def _validate_disjoint_intervals(
    label: str,
    intervals: Sequence[tuple[str, int, int]],
) -> None:
    """Reject malformed or overlapping inclusive address intervals."""

    ordered: list[tuple[int, int, str]] = []
    for name, start, end in intervals:
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 0
            or end < start
        ):
            raise GranularityError(f"{label} contains an invalid interval: {name}")
        ordered.append((start, end, name))
    ordered.sort()
    for previous, current in zip(ordered, ordered[1:]):
        if current[0] <= previous[1]:
            raise GranularityError(
                f"{label} overlap: {previous[2]} and {current[2]}"
            )


def _validate_range_layout() -> None:
    """Ensure reserved subtraction leaves disjoint protected/RAM ranges."""

    derived_system_ram = _derive_system_ram(RAW_SYSTEM_RAM)
    if derived_system_ram != SYSTEM_RAM:
        raise GranularityError(
            "SYSTEM_RAM does not equal RAW_SYSTEM_RAM minus reserved/excluded ranges"
        )

    protected = []
    for name, base, size in PROTECTED_REGIONS:
        if (
            not isinstance(base, int)
            or isinstance(base, bool)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or base < 0
            or size <= 0
        ):
            raise GranularityError(f"protected regions contains an invalid interval: {name}")
        protected.append((name, base, base + size - 1))
    system_ram = []
    for start, end in SYSTEM_RAM:
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 0
            or end < start
        ):
            raise GranularityError("System RAM contains an invalid interval")
        system_ram.append((f"System RAM 0x{start:x}-0x{end:x}", start, end))
    reserved = []
    for name, base, size in RESERVED_NESTED_IN_SYSTEM_RAM:
        if (
            not isinstance(base, int)
            or isinstance(base, bool)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or base < 0
            or size <= 0
        ):
            raise GranularityError(f"reserved subtractions contains an invalid interval: {name}")
        reserved.append((name, base, base + size - 1))
    _validate_disjoint_intervals("protected regions", protected)
    _validate_disjoint_intervals("System RAM", system_ram)
    _validate_disjoint_intervals("reserved subtractions", reserved)

    for protected_name, protected_start, protected_end in protected:
        for ram_name, ram_start, ram_end in system_ram:
            if protected_start <= ram_end and ram_start <= protected_end:
                raise GranularityError(
                    f"protected/System RAM overlap after subtraction: "
                    f"{protected_name} and {ram_name}"
                )

    for reserved_name, reserved_start, reserved_end in reserved:
        if not any(
            protected_start <= reserved_start
            and reserved_end <= protected_end
            for _, protected_start, protected_end in protected
        ):
            raise GranularityError(
                f"reserved subtraction is not contained in a protected region: "
                f"{reserved_name}"
            )
        for ram_name, ram_start, ram_end in system_ram:
            if reserved_start <= ram_end and ram_start <= reserved_end:
                raise GranularityError(
                    f"reserved/System RAM overlap after subtraction: "
                    f"{reserved_name} and {ram_name}"
                )


def _read_pinned(path: pathlib.Path, pin: Mapping[str, object], label: str) -> bytes:
    """Read one tracked source file and fail closed if its bytes moved."""

    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except OSError as exc:
        raise GranularityError(f"{label} cannot be opened without following links") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != pin["size_bytes"]:
            raise GranularityError(f"{label} size/type differs from the pinned source")
        data = bytearray()
        while len(data) < info.st_size:
            chunk = os.read(fd, min(1 << 20, info.st_size - len(data)))
            if not chunk:
                raise GranularityError(f"{label} was truncated while being read")
            data.extend(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        after.st_dev != info.st_dev
        or after.st_ino != info.st_ino
        or after.st_size != info.st_size
        or not stat.S_ISREG(after.st_mode)
    ):
        raise GranularityError(f"{label} changed while being read")
    payload = bytes(data)
    if hashlib.sha256(payload).hexdigest() != pin["sha256"]:
        raise GranularityError(f"{label} SHA-256 differs from the pinned source")
    return payload


def source_descriptors() -> dict[str, dict[str, object]]:
    """Validate and return sanitized descriptors for the exact public inputs."""

    paths = {
        "relation_manifest": RELATION_SOURCE,
        "high_bit_manifest": HIGH_BIT_SOURCE,
        "memory_map": MEMORY_MAP_SOURCE,
    }
    checked: dict[str, dict[str, object]] = {}
    for kind, path in paths.items():
        pin = SOURCE_PINS[kind]
        _read_pinned(path, pin, kind)
        checked[kind] = dict(pin)
    return checked


def _decode_json_object(data: bytes, label: str) -> dict[str, object]:
    """Decode one pinned JSON object while rejecting duplicate object keys."""

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise GranularityError(f"{label} contains duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
        )
    except GranularityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GranularityError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise GranularityError(f"{label} is not a JSON object")
    return value


def _parse_hex_range(value: str, label: str) -> tuple[int, int]:
    match = re.fullmatch(r"0x([0-9a-fA-F]+)\s*[\-\u2013]\s*0x([0-9a-fA-F]+)", value.strip())
    if match is None:
        raise GranularityError(f"{label} contains an invalid address range: {value!r}")
    start, end = (int(part, 16) for part in match.groups())
    if end < start:
        raise GranularityError(f"{label} contains a descending address range")
    return start, end


def parse_memory_map_ranges(data: bytes | str) -> dict[str, object]:
    """Parse the exact fixed-range and System-RAM sections of MEMORY_MAP.md."""

    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GranularityError("MEMORY_MAP.md is not valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise GranularityError("MEMORY_MAP input must be bytes or text")

    fixed_match = re.search(
        r"^## Fixed reserved ranges\s*$([\s\S]*?)(?=^## )",
        text,
        re.MULTILINE,
    )
    if fixed_match is None:
        raise GranularityError("MEMORY_MAP.md fixed-range section is missing")
    fixed_rows: list[tuple[str, tuple[int, int]]] = []
    table_pattern = re.compile(
        r"^\|\s*`([^`]+)`\s*\|\s*[^|]+\|\s*([^|]+?)\s*\|",
        re.MULTILINE,
    )
    for match in table_pattern.finditer(fixed_match.group(1)):
        role = match.group(2).strip().strip("`")
        fixed_rows.append((role, _parse_hex_range(match.group(1), "fixed ranges")))
    if len(fixed_rows) != len(PROTECTED_REGIONS):
        raise GranularityError(
            f"MEMORY_MAP.md fixed-range row count {len(fixed_rows)} differs from expected {len(PROTECTED_REGIONS)}"
        )
    expected_roles = ("hyp_mem", "TIMA", "RKP", "uh_heap_region", "qseecom_region")
    if tuple(role for role, _ in fixed_rows) != expected_roles:
        raise GranularityError("MEMORY_MAP.md fixed-range roles changed")
    parsed_protected = tuple(
        (name, start, end - start + 1)
        for (name, _, _), (_, (start, end)) in zip(PROTECTED_REGIONS, fixed_rows)
    )

    iomem_match = re.search(
        r"^## `/proc/iomem` observations\s*$([\s\S]*?)(?=^## )",
        text,
        re.MULTILINE,
    )
    if iomem_match is None:
        raise GranularityError("MEMORY_MAP.md /proc/iomem section is missing")
    code_blocks = re.findall(r"```text\s*([\s\S]*?)```", iomem_match.group(1))
    if len(code_blocks) != 1:
        raise GranularityError("MEMORY_MAP.md /proc/iomem range block is ambiguous")
    raw_rows = []
    for line in code_blocks[0].splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        raw_rows.append(_parse_hex_range(stripped, "System RAM"))
    if not raw_rows:
        raise GranularityError("MEMORY_MAP.md System RAM range block is empty")
    return {
        "protected_regions": parsed_protected,
        "raw_system_ram": tuple(raw_rows),
    }


def _validate_memory_map_semantics(data: bytes) -> dict[str, object]:
    """Pin parsed memory-map values to the constants used by the calculation."""

    parsed = parse_memory_map_ranges(data)
    expected_protected = tuple(PROTECTED_REGIONS)
    if parsed["protected_regions"] != expected_protected:
        raise GranularityError("MEMORY_MAP protected ranges differ from the pinned calculation")
    if parsed["raw_system_ram"] != RAW_SYSTEM_RAM:
        raise GranularityError("MEMORY_MAP System RAM ranges differ from the pinned calculation")
    derived = _derive_system_ram(parsed["raw_system_ram"])
    if derived != SYSTEM_RAM:
        raise GranularityError("MEMORY_MAP-derived System RAM subtraction differs")
    return {
        "protected_regions_match": True,
        "raw_system_ram_match": True,
        "derived_system_ram_match": True,
        "protected_region_count": len(parsed["protected_regions"]),
        "raw_system_ram_count": len(parsed["raw_system_ram"]),
        "protected_regions": [
            {"name": name, "base": f"0x{base:x}", "size": size}
            for name, base, size in parsed["protected_regions"]
        ],
        "raw_system_ram": [
            {"start": f"0x{start:x}", "end": f"0x{end:x}"}
            for start, end in parsed["raw_system_ram"]
        ],
    }


def source_semantics(relation: Mapping[int, int] = RELATION) -> dict[str, object]:
    """Cross-check the pinned manifests' semantic fields, not just their hashes."""

    relation_bytes = _read_pinned(
        RELATION_SOURCE, SOURCE_PINS["relation_manifest"], "relation_manifest"
    )
    relation_manifest = _decode_json_object(
        relation_bytes,
        "relation_manifest",
    )
    high_bit_manifest = _decode_json_object(
        _read_pinned(HIGH_BIT_SOURCE, SOURCE_PINS["high_bit_manifest"], "high_bit_manifest"),
        "high_bit_manifest",
    )
    memory_map_bytes = _read_pinned(
        MEMORY_MAP_SOURCE, SOURCE_PINS["memory_map"], "memory_map"
    )
    relation_rank_record = relation_manifest.get("rank")
    relation_kernel = relation_manifest.get("kernel")
    if (
        not isinstance(relation_rank_record, Mapping)
        or relation_rank_record.get("rank") != 3
        or relation_rank_record.get("resolved") is not True
        or not isinstance(relation_kernel, Mapping)
        or relation_kernel.get("unique") is not True
    ):
        raise GranularityError("023R source does not retain a resolved unique rank-3 result")
    source_basis = relation_kernel.get("example_kernel_basis")
    if (
        not isinstance(source_basis, list)
        or len(source_basis) != len(SOURCE_KERNEL_BASIS_HEX)
        or any(
            not isinstance(value, str)
            or re.fullmatch(r"0x[0-9a-fA-F]+", value) is None
            for value in source_basis
        )
        or tuple(source_basis) != SOURCE_KERNEL_BASIS_HEX
    ):
        raise GranularityError("023R source kernel basis changed or is malformed")
    source_basis_values = tuple(int(value, 16) for value in source_basis)
    source_mask = ((1 << SOURCE_MODEL_WIDTH) - 1) << SOURCE_MODEL_BITS[0]
    if any(value == 0 or value & ~source_mask for value in source_basis_values):
        raise GranularityError("023R kernel basis leaves the declared model domain")
    source_relation = {bit: relation.get(bit, 0) for bit in SOURCE_MODEL_BITS}
    if relation_rank(source_relation) != BANK_OUTPUT_BITS:
        raise GranularityError("candidate relation is not rank three in the 023R domain")
    if any(bank_class(value, relation) != 0 for value in source_basis_values):
        raise GranularityError("candidate relation does not contain the 023R kernel basis")
    source_basis_points = tuple(value >> SOURCE_MODEL_BITS[0] for value in source_basis_values)
    if _row_reduce_rank(source_basis_points) != len(source_basis_values):
        raise GranularityError("023R example kernel basis is not independent")
    source_kernel_match = True

    expected_matches = {
        "PA25": [14, 21],
        "PA26": [19],
        "PA27": [13, 20],
    }
    if high_bit_manifest.get("matches") != expected_matches:
        raise GranularityError("V016 source high-bit matches differ from the declared cross-check")
    if high_bit_manifest.get("class_c") != "TRANSFORM ONLY":
        raise GranularityError("V016 source is not a Class-C result")
    memory_map_check = _validate_memory_map_semantics(memory_map_bytes)
    return {
        "relation_rank": relation_rank_record["rank"],
        "relation_unique": relation_kernel["unique"],
        "relation_kernel_basis": [f"0x{value:x}" for value in source_basis_values],
        "relation_kernel_basis_rank": _row_reduce_rank(source_basis_points),
        "relation_kernel_basis_matches_source": source_kernel_match,
        "relation_kernel_basis_scope": "ALLOCATION_OFFSET_MODEL_COORDINATES_BITS_13_24",
        "v016_matches": expected_matches,
        "v016_class": high_bit_manifest["class_c"],
        "memory_map": memory_map_check,
    }


def relation_rank(relation: Mapping[int, int]) -> int:
    """Return the GF(2) rank of the relation's vector columns."""

    basis: list[int] = []
    for bit, vector in sorted(relation.items()):
        if not isinstance(bit, int) or isinstance(bit, bool) or bit < 0:
            raise GranularityError("relation bit is not a non-negative integer")
        if not isinstance(vector, int) or isinstance(vector, bool) or not 0 <= vector < 8:
            raise GranularityError("relation vector is outside the 3-bit bank space")
        reduced = vector
        for member in basis:
            reduced = min(reduced, reduced ^ member)
        if reduced:
            basis.append(reduced)
            basis.sort(reverse=True)
    return len(basis)


def bank_class(address: int, relation: Mapping[int, int] = RELATION) -> int:
    """f(address) as a 3-bit bank vector."""
    value = 0
    for bit, contribution in relation.items():
        if (address >> bit) & 1:
            value ^= contribution
    return value


def _row_reduce_rank(rows: Sequence[int]) -> int:
    """Return the rank of binary row masks using deterministic GF(2) reduction."""

    basis: list[int] = []
    for row in rows:
        if not isinstance(row, int) or isinstance(row, bool) or row < 0:
            raise GranularityError("a GF(2) row must be a non-negative integer")
        reduced = row
        for member in basis:
            reduced = min(reduced, reduced ^ member)
        if reduced:
            basis.append(reduced)
            basis.sort(reverse=True)
    return len(basis)


def _model_row_masks(relation: Mapping[int, int] = RELATION) -> tuple[int, ...]:
    """Represent each bank output bit as a mask over ``MODEL_BITS``.

    The returned rows are an algebraic representation only.  A row mask bit at
    position ``i`` denotes model input bit ``MODEL_BITS[i]``; it is not a PFN or
    a physical-address proof.
    """

    unknown = set(relation) - set(MODEL_BITS)
    if unknown:
        raise GranularityError(
            "relation contains bits outside the declared model domain: "
            + ",".join(str(bit) for bit in sorted(unknown))
        )
    rows = []
    for output_bit in range(BANK_OUTPUT_BITS):
        row = 0
        for index, bit in enumerate(MODEL_BITS):
            vector = relation.get(bit, 0)
            if not isinstance(vector, int) or isinstance(vector, bool) or not 0 <= vector < 8:
                raise GranularityError("relation vector is outside the 3-bit bank space")
            if (vector >> output_bit) & 1:
                row |= 1 << index
        rows.append(row)
    return tuple(rows)


def _model_point(address: int) -> int:
    """Compress an address-model value to positions 0..14 without naming PA."""

    if not isinstance(address, int) or isinstance(address, bool) or address < 0:
        raise GranularityError("model point must be a non-negative integer")
    if address & ~(((1 << MODEL_WIDTH) - 1) << MODEL_BITS[0]):
        raise GranularityError("model point contains bits outside MODEL_BITS")
    return (address >> MODEL_BITS[0]) & ((1 << MODEL_WIDTH) - 1)


def _parity(row: int, point: int) -> int:
    return (row & point).bit_count() & 1


def _coordinate_rows(
    relation: Mapping[int, int] = RELATION,
    extra_bits: Sequence[int] = DIAGNOSTIC_EXTRA_BITS,
) -> tuple[int, ...]:
    """Build a complete-coordinate *countermodel* with bank rows first.

    The extra rows preserve selected raw model bits as abstract coordinate
    components.  They intentionally do not claim that a real SM8150 DRAM
    controller exposes these rows or assigns them to row/channel/column pins.
    """

    bank_rows = _model_row_masks(relation)
    rows = list(bank_rows)
    for bit in extra_bits:
        if bit not in MODEL_BITS:
            raise GranularityError(f"extra coordinate bit {bit} is outside MODEL_BITS")
        rows.append(1 << MODEL_BITS.index(bit))
    return tuple(rows)


def _first_null_vector(rows: Sequence[int]) -> int | None:
    """Return the first non-zero null vector in model coordinates, if any."""

    for point in range(1, 1 << MODEL_WIDTH):
        if all(_parity(row, point) == 0 for row in rows):
            return point
    return None


def _model_address(point: int) -> int:
    return int(point) << MODEL_BITS[0]


def _coordinate_countermodel(
    name: str,
    relation: Mapping[int, int],
    extra_bits: Sequence[int],
    interpretation: str,
) -> dict[str, object]:
    """Summarise one abstract completion of the observed bank projection."""

    rows = _coordinate_rows(relation, extra_bits)
    rank = _row_reduce_rank(rows)
    domain_size = 1 << MODEL_WIDTH
    output_count = 1 << rank
    fiber_size = 1 << (MODEL_WIDTH - rank)
    null_point = _first_null_vector(rows)
    if rank == MODEL_WIDTH and null_point is not None:
        raise GranularityError(f"{name} is full rank but has a null vector")
    if rank < MODEL_WIDTH and null_point is None:
        raise GranularityError(f"{name} is rank deficient but has no null vector")
    null_address = None if null_point is None else _model_address(null_point)
    bank_rows = _model_row_masks(relation)
    projection_matches = tuple(rows[:BANK_OUTPUT_BITS]) == bank_rows
    return {
        "name": name,
        "kind": "ABSTRACT_GF2_COMPLETION",
        "coordinate_domain": "ALLOCATION_OFFSET_MODEL_COORDINATES",
        "interpretation": interpretation,
        "bank_projection_preserved": projection_matches,
        "bank_output_rows": [f"0x{row:x}" for row in bank_rows],
        "extra_coordinate_bits": list(extra_bits),
        "row_count": len(rows),
        "matrix_rank": rank,
        "model_input_width": MODEL_WIDTH,
        "model_domain_size": domain_size,
        "distinct_complete_coordinates": output_count,
        "fiber_size": fiber_size,
        "injective_over_model_domain": rank == MODEL_WIDTH,
        "collision_pair_count": (
            output_count * fiber_size * (fiber_size - 1) // 2
        ),
        "first_nonzero_null_point": (
            None if null_point is None else f"0x{null_point:x}"
        ),
        "first_nonzero_null_address": (
            None if null_address is None else f"0x{null_address:x}"
        ),
    }


def countermodel_analysis(relation: Mapping[int, int] = RELATION) -> dict[str, object]:
    """Show why a bank relation cannot decide complete-coordinate injectivity.

    All three entries share exactly the same first three output rows (the
    recovered bank relation).  One completion is injective, one intentionally
    drops a model coordinate, and one retains only the bank projection.  This
    is a constructive underdetermination proof, not a silicon observation.
    """

    if relation_rank(relation) != BANK_OUTPUT_BITS:
        raise GranularityError("countermodels require a rank-3 bank relation")
    models = [
        _coordinate_countermodel(
            "injective_complete_surrogate",
            relation,
            DIAGNOSTIC_EXTRA_BITS,
            "bank projection plus every retained high model bit; injective abstract completion",
        ),
        _coordinate_countermodel(
            "folded_complete_surrogate",
            relation,
            FOLDED_EXTRA_BITS,
            "bank projection plus one fewer high model bit; deliberately non-injective completion",
        ),
        _coordinate_countermodel(
            "bank_only_projection",
            relation,
            (),
            "bank projection only; not a proposed DRAM coordinate",
        ),
    ]
    if not all(model["bank_projection_preserved"] for model in models):
        raise GranularityError("a countermodel changed the observed bank projection")
    injective = next(model for model in models if model["name"] == "injective_complete_surrogate")
    folded = next(model for model in models if model["name"] == "folded_complete_surrogate")
    bank_only = next(model for model in models if model["name"] == "bank_only_projection")
    if not injective["injective_over_model_domain"]:
        raise GranularityError("injective completion unexpectedly lost injectivity")
    if folded["injective_over_model_domain"] or bank_only["injective_over_model_domain"]:
        raise GranularityError("non-injective completion unexpectedly became injective")
    return {
        "status": "PROVED_ABSTRACT_UNDERDETERMINATION",
        "model_bits": list(MODEL_BITS),
        "model_width": MODEL_WIDTH,
        "bank_output_width": BANK_OUTPUT_BITS,
        "bank_projection_rows": [f"0x{row:x}" for row in _model_row_masks(relation)],
        "models": models,
        "same_bank_projection_different_completions": True,
        "complete_coordinate_injectivity": "UNKNOWN_FOR_SILICON",
        "physical_alias": "UNKNOWN_NOT_TESTED",
    }


def protection_ordering_countermodels() -> dict[str, object]:
    """Return the two abstract orderings left open by the host evidence."""

    return {
        "status": "UNKNOWN_FOR_SILICON",
        "models": [
            {
                "name": "pre_transform_check_then_noninjective_map",
                "security_decision": "input_address_or_pre_transform",
                "map": "noninjective_complete_coordinate",
                "result": "BYPASS_POSSIBLE_IN_ABSTRACT_MODEL",
            },
            {
                "name": "post_transform_complete_check",
                "security_decision": "complete_post_transform_coordinate",
                "map": "same_noninjective_complete_coordinate",
                "result": "BYPASS_BLOCKED_IN_ABSTRACT_MODEL",
            },
            {
                "name": "post_transform_bank_only_check",
                "security_decision": "bank_projection_only",
                "map": "same_bank_projection",
                "result": "CANNOT_SEPARATE_LISTED_WIDE_RANGES",
            },
        ],
        "hardware_ordering": "UNKNOWN",
        "hardware_bypass": "UNKNOWN_NOT_TESTED",
    }


def check_v016_consistency(
    relation: Mapping[int, int] = RELATION,
    equalities: Mapping[int, Sequence[int]] = V016_EQUALITIES,
) -> dict:
    """Verification 016's discrimination must agree with the solved table."""
    rows, disagreements = [], []
    for high, lowers in sorted(equalities.items()):
        for lower in lowers:
            agrees = relation[high] == relation[lower]
            rows.append({
                "high": high, "lower": lower,
                "high_vector": relation[high], "lower_vector": relation[lower],
                "agrees": agrees,
            })
            if not agrees:
                disagreements.append((high, lower))
    return {"rows": rows, "agrees": not disagreements,
            "disagreements": disagreements}


def class_change_granularity(relation: Mapping[int, int] = RELATION) -> int:
    """The minimum span at which a bank-class change can occur."""
    contributing = [bit for bit, vector in relation.items() if vector]
    if not contributing:
        raise GranularityError("the relation has no contributing bit")
    return 1 << min(contributing)


def span_to_cover_all_classes(relation: Mapping[int, int] = RELATION,
                              aligned: bool = True) -> int:
    """Smallest region size guaranteed to cover every class.

    Walking the contributing bits from the bottom, the classes reachable are the
    span of the vectors seen so far.  Once that span is the whole space, a
    region large enough to vary those bits covers every class.  The aligned
    answer assumes the region begins on that span boundary.  At an arbitrary
    base, the conservative guarantee is twice as wide so that the interval is
    certain to contain an aligned span.
    """
    basis: list[int] = []
    for bit in sorted(bit for bit, vector in relation.items() if vector):
        vector = relation[bit]
        for member in basis:
            vector = min(vector, vector ^ member)
        if vector:
            basis.append(vector)
            basis.sort(reverse=True)
        if len(basis) == 3:
            span = 1 << (bit + 1)
            return span if aligned else span << 1
    raise GranularityError("the relation never reaches full rank")


def classes_in_range(base: int, size: int,
                     relation: Mapping[int, int] = RELATION,
                     cap_pages: int | None = None) -> dict:
    """Count model-projected pages per bank class across a declared range."""
    if not isinstance(base, int) or isinstance(base, bool) or base < 0:
        raise GranularityError("a range base must be a non-negative integer")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise GranularityError("a range needs a positive size")
    if size % PAGE_BYTES:
        raise GranularityError("a range size must be page aligned")
    if cap_pages is not None and (not isinstance(cap_pages, int) or isinstance(cap_pages, bool) or cap_pages <= 0):
        raise GranularityError("cap_pages must be positive or None")
    pages = size // PAGE_BYTES
    counted = pages if cap_pages is None else min(pages, cap_pages)
    histogram = {index: 0 for index in range(8)}
    for page in range(counted):
        histogram[bank_class(base + page * PAGE_BYTES, relation)] += 1
    return {
        "base": f"0x{base:x}",
        "size": size,
        "pages": pages,
        "pages_counted": counted,
        "truncated": counted < pages,
        "histogram": histogram,
        "classes_covered": sum(1 for value in histogram.values() if value),
    }


def analyse(relation: Mapping[int, int] = RELATION) -> dict:
    _validate_range_layout()
    rank = relation_rank(relation)
    if rank != 3:
        raise GranularityError(f"expected rank-3 relation, got rank {rank}")
    source_cross_check = source_semantics(relation)
    source_equalities = {
        int(key[2:]): tuple(value)
        for key, value in source_cross_check["v016_matches"].items()
    }
    consistency = check_v016_consistency(relation, source_equalities)
    granularity = class_change_granularity(relation)
    covering = span_to_cover_all_classes(relation, aligned=True)
    unaligned_covering = span_to_cover_all_classes(relation, aligned=False)
    inputs = source_descriptors()
    countermodels = countermodel_analysis(relation)
    ordering_models = protection_ordering_countermodels()

    protected = []
    for name, base, size in PROTECTED_REGIONS:
        entry = classes_in_range(base, size, relation)
        entry["name"] = name
        entry["coordinate_scope"] = "ALLOCATION_OFFSET_MODEL_COORDINATES"
        entry["range_projection_scope"] = "MODEL_PROJECTED_ONLY"
        protected.append(entry)

    unprotected = []
    for start, end in SYSTEM_RAM:
        entry = classes_in_range(start, end - start + 1, relation)
        entry["name"] = f"System RAM 0x{start:x}-0x{end:x}"
        entry["coordinate_scope"] = "ALLOCATION_OFFSET_MODEL_COORDINATES"
        entry["range_projection_scope"] = "MODEL_PROJECTED_ONLY"
        unprotected.append(entry)

    every_protected = all(e["classes_covered"] == 8 for e in protected)
    every_unprotected = all(e["classes_covered"] == 8 for e in unprotected)

    return {
        "schema": SCHEMA,
        "classification": "CLASS C (TRANSFORM ONLY)",
        "scope": {
            "coordinate_domain": "ALLOCATION_OFFSET_MODEL_COORDINATES",
            "range_projection_scope": "MODEL_PROJECTED_ONLY",
            "enforcement_claim": "BANK_ONLY_POST_DECODE_SHAPE_ONLY",
            "protected_regions": "EXACT_LISTED_DEVICE_TREE_REGIONS_AS_MODEL_PROJECTION_INPUTS",
            "physical_mapping": "UNKNOWN_PAGEMAP_BLIND",
            "complete_coordinate": "UNKNOWN",
            "transform_mutability": "UNKNOWN",
            "protection_ordering": "UNKNOWN",
        },
        "inputs": inputs,
        "source_cross_check": source_cross_check,
        "relation": {str(bit): vector for bit, vector in sorted(relation.items())},
        "rank": rank,
        "v016_consistency": consistency,
        "class_change_granularity_bytes": granularity,
        "span_covering_all_classes_bytes": covering,
        "span_covering_all_classes_unaligned_bytes": unaligned_covering,
        "countermodels": countermodels,
        "protection_ordering_countermodels": ordering_models,
        "protected_regions": protected,
        "unprotected_ranges": unprotected,
        "reserved_subtractions": [
            {"name": name, "base": f"0x{base:x}", "size": size}
            for name, base, size in RESERVED_NESTED_IN_SYSTEM_RAM
        ],
        "unprotected_exclusions": [
            {"base": f"0x{start:x}", "end": f"0x{end:x}", "reason": reason}
            for start, end, reason in SYSTEM_RAM_EXCLUDED
        ],
        "all_protected_cover_every_class": every_protected,
        "all_unprotected_cover_every_class": every_unprotected,
        "bank_granular_check_can_separate": not (every_protected and every_unprotected),
        "bank_granular_check_scope": "MODEL_PROJECTED_ONLY",
        "range_histogram_scope": "ALLOCATION_OFFSET_MODEL_COORDINATES",
        "claims": {
            "PROVED": [
                "rank_3_relation_in_declared_model_coordinates",
                "minimum_8KiB_class_change_span_in_declared_model",
                "64KiB_aligned_model_projection_covers_all_8_bank_classes",
                "128KiB_unaligned_model_projection_covers_all_8_bank_classes",
                "listed_ranges_cover_all_8_model_projected_classes",
                "memory_map_ranges_match_pinned_source",
                "023R_kernel_basis_matches_candidate_relation_kernel",
                "V016_high_bit_equalities_match_023R_relation",
                "same_bank_projection_has_both_injective_and_noninjective_abstract_completions",
                "bank_relation_alone_does_not_determine_complete_coordinate_injectivity",
            ],
            "SUPPORTED": [
                "narrow_bank_only_post_decode_check_is_not_a_separator_for_listed_ranges_in_model_projection",
            ],
            "HYPOTHESIS": [],
            "UNKNOWN": [
                "actual_enforcement_ordering",
                "complete_dram_coordinate_and_physical_mapping",
                "transform_state_mutability",
                "global_writer_or_register_absence",
                "protected_memory_reach_or_bypass",
                "PA28_AND_ABOVE",
                "actual_complete_coordinate_injectivity",
                "actual_protection_ordering",
            ],
            "REFUTED": [
                "bank_only_post_decode_check_separates_listed_ranges_in_model_projection",
                "rank_3_bank_relation_alone_proves_complete_coordinate_alias",
                "rank_3_bank_relation_alone_proves_complete_coordinate_injectivity",
            ],
        },
    }


def encode_public(result: Mapping[str, object]) -> bytes:
    """Canonical, path-free JSON encoding for a fresh public manifest."""

    return (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def write_public(path: pathlib.Path, result: Mapping[str, object]) -> dict[str, object]:
    """Write once with O_EXCL/O_NOFOLLOW and mode 0644; never clobber."""

    path = pathlib.Path(path)
    if not path.parent.is_dir():
        raise GranularityError(f"manifest parent does not exist: {path.parent}")
    payload = encode_public(result)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise GranularityError(f"manifest output already exists or is unsafe: {path}") from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise GranularityError("manifest write made no progress")
            view = view[written:]
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    return {
        "basename": path.name,
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "mode": "0644",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    try:
        result = analyse()
        publication = write_public(pathlib.Path(args.output), result)
    except (GranularityError, OSError) as exc:
        print(f"verification-017: {exc}", file=__import__("sys").stderr)
        return 2

    print(f"relation rank 3, minimum class-change span "
          f"{result['class_change_granularity_bytes']} bytes; "
          f"{result['span_covering_all_classes_bytes']} bytes covers all 8 "
          f"when aligned; arbitrary-base guarantee "
          f"{result['span_covering_all_classes_unaligned_bytes']} bytes")
    print(f"Verification 016 agrees with the solved table: "
          f"{result['v016_consistency']['agrees']}")
    print()
    for entry in result["protected_regions"] + result["unprotected_ranges"]:
        print(f"  {entry['name']:<34} {entry['pages']:>9} pages  "
              f"classes covered {entry['classes_covered']}/8")
    print()
    print(f"a bank-granular check can separate protected from unprotected: "
          f"{result['bank_granular_check_can_separate']}")
    print(f"published {publication['basename']} {publication['size_bytes']} bytes "
          f"sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
