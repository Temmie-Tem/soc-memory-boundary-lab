#!/usr/bin/env python3
"""Decode every XPU protected region in the exact A90 TrustZone image.

Verification 009 decoded five region ranges and left the other 1,721 as bare
counts.  Every later document that said "no address inside <range> appears in
the retained XPU inventories" was therefore comparing against 0.3% of the
declared policy, which is a statement about this project's extraction scope and
not about the target's protection.

This tool closes that gap: it walks all region tables for all XPU instances in
both selector branches and answers containment questions against the complete
decoded set.  It is host-only.  It performs no device, MMIO, SMC or firmware
write, and it emits no firmware bytes -- only decoded record fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.a90_acm_snapshot import json_bytes, write_new
from tools.sm8150_xpu_policy_inventory import (
    decode_mpu_region_permissions,
    parse_mpu_regions,
    region_contains,
)
from tools.xbl_dcb_inventory import parse_elf64_load_segments

SCHEMA = "sm8150-xpu-region-coverage-v1"

# The exact Verification 009 TrustZone input.  Pinned so a coverage claim can
# never silently drift to another build.
TZ_SHA256 = "a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab"
TZ_SIZE = 4_194_304

# The 009 manifest supplies the instance descriptors; this tool never re-derives
# them, so the two results cannot disagree about which instances exist.
POLICY_MANIFEST = (
    REPO_ROOT / "evidence/manifests/009-xpu-policy-inventory-20260825-01.manifest.json"
)
POLICY_MANIFEST_SHA256 = (
    "f5c661af73cd6b4a0d423ef44a59b11cba0e208ad178670ff2dabf097bf2e4e6"
)

# A region table pointer must land inside the image and the count must be sane.
# These bound the walk so a corrupt descriptor cannot drive an unbounded read.
MAX_REGIONS_PER_INSTANCE = 4096
MPU_REGION_RECORD_SIZE = 32

# The 32-byte `<IIIIQQ` record that Verification 009 validated is the *MPU*
# region layout.  Applying it to the XPU/RPU/APU/BAM instances produces
# 717 records with ends above 2^40 and 710 table pointers outside the image --
# that is a wrong layout, not a policy finding.  Those classes are reported as
# undecoded rather than decoded into noise.
MPU_CLASS_SUFFIX = "_MPU"
MPU_CLASS_EXTRA = frozenset({"QM_MPU_CFG"})

# An address this large is not an SM8150 physical address.  Any such record
# among MPU-class instances means the layout assumption broke and the walk must
# fail rather than publish.
IMPLAUSIBLE_END = 1 << 40

# Unused region slots are written as 0xffffffff start and end.  They are counted
# but never answer a containment query.
UNUSED_SLOT_MARKER = 0xFFFFFFFF


def is_mpu_class(name: str) -> bool:
    return name.endswith(MPU_CLASS_SUFFIX) or name in MPU_CLASS_EXTRA

# Queried apertures.  `apcs_glb` is the open question Verification 009 could not
# answer; the others are retained anchors whose expected answer is known, so a
# wrong result here is visible rather than silent.
QUERIES: dict[str, tuple[int, int]] = {
    "apcs_glb_mailbox": (0x17C00000, 0x17C01000),
    "apcs_syscon_ipc": (0x17C0000C, 0x17C00010),
    "apss_watchdog": (0x17C10000, 0x17C11000),
    "qhs_llcc_remapper_instance0": (0x09248080, 0x09248084),
    "qhs_llcc_remapper_page": (0x09248000, 0x09249000),
}

# `qhs_llcc_remapper_page` must come back covered: Verification 009 proved a
# narrow DC_NOC_BROADCAST_MPU region there.  If the walk cannot reproduce that,
# the walk is wrong and the tool says so instead of publishing a coverage claim.
CONTROL_QUERY = "qhs_llcc_remapper_page"


class CoverageError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb", closefd=True) as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_pinned(path: Path, expected_sha: str, expected_size: int | None = None) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise CoverageError(f"{path.name} is not a regular file")
    actual = sha256_file(path)
    if actual != expected_sha:
        raise CoverageError(f"{path.name} SHA-256 {actual} != pinned {expected_sha}")
    data = path.read_bytes()
    if expected_size is not None and len(data) != expected_size:
        raise CoverageError(f"{path.name} is {len(data)} bytes, expected {expected_size}")
    return data


def instance_descriptors(manifest: Mapping[str, object]) -> dict[str, list[dict]]:
    tables = manifest["policy_tables"]
    out: dict[str, list[dict]] = {}
    for branch, table in tables.items():
        descriptors = []
        for record in table["descriptors"]:
            count = int(record["region_count"])
            if not 0 <= count <= MAX_REGIONS_PER_INSTANCE:
                raise CoverageError(
                    f"{branch}/{record['name']} declares {count} regions, outside bounds"
                )
            descriptors.append(
                {
                    "name": str(record["name"]),
                    "base": int(str(record["base"]), 16),
                    "resource_id": int(str(record["resource_id"]), 16),
                    "region_count": count,
                    "region_vaddr": int(str(record["region_vaddr"]), 16),
                }
            )
        out[branch] = descriptors
    return out


def walk_branch(
    data: bytes, segments: Sequence, descriptors: Sequence[Mapping]
) -> tuple[list[dict], list[dict], list[dict]]:
    """Decode every MPU-class region.  Returns (regions, unused, not_decoded)."""
    regions: list[dict] = []
    unused: list[dict] = []
    not_decoded: list[dict] = []
    for descriptor in descriptors:
        name = descriptor["name"]
        if not is_mpu_class(name):
            not_decoded.append(
                {
                    "instance": name,
                    "resource_id": f"0x{descriptor['resource_id']:x}",
                    "region_count": descriptor["region_count"],
                    "reason": "non-MPU instance; region record layout is UNKNOWN",
                }
            )
            continue
        if descriptor["region_count"] == 0:
            continue
        records = parse_mpu_regions(
            data, segments, descriptor["region_vaddr"], descriptor["region_count"]
        )
        for record in records:
            start = int(record["start"])
            end = int(record["end_exclusive"])
            common = {
                "instance": name,
                "instance_base": f"0x{descriptor['base']:08x}",
                "resource_id": f"0x{descriptor['resource_id']:x}",
                "ordinal": record["ordinal"],
            }
            if start == UNUSED_SLOT_MARKER and end == UNUSED_SLOT_MARKER:
                unused.append(common)
                continue
            if end < start or end >= IMPLAUSIBLE_END:
                raise CoverageError(
                    f"{name} ordinal {record['ordinal']} decodes to "
                    f"0x{start:x}..0x{end:x}, which is not an SM8150 physical "
                    "range; the MPU record layout assumption is broken"
                )
            regions.append(
                {
                    **common,
                    "start": start,
                    "end_exclusive": end,
                    "size": end - start,
                    "flags": f"0x{int(record['flags']):x}",
                    "read_vmid": f"0x{int(record['read_vmid']):08x}",
                    "write_vmid": f"0x{int(record['write_vmid']):08x}",
                }
            )
    return regions, unused, not_decoded


def answer_query(regions: Sequence[Mapping], lo: int, hi: int) -> dict:
    """Every decoded region overlapping [lo, hi)."""
    hits = []
    for region in regions:
        if region["start"] < hi and lo < region["end_exclusive"]:
            permissions = decode_mpu_region_permissions(
                {
                    "flags": int(region["flags"], 16),
                    "read_vmid": int(region["read_vmid"], 16),
                    "write_vmid": int(region["write_vmid"], 16),
                    "start": region["start"],
                    "end_exclusive": region["end_exclusive"],
                }
            )
            # The decoder names these `hlos_present_in_*_mask`.  Reading any
            # other key would silently yield False for every region and make the
            # grant columns vacuous.
            hits.append(
                {
                    "instance": region["instance"],
                    "resource_id": region["resource_id"],
                    "ordinal": region["ordinal"],
                    "range": f"0x{region['start']:x}..0x{region['end_exclusive']:x}",
                    "read_vmid": region["read_vmid"],
                    "write_vmid": region["write_vmid"],
                    "owner": permissions["owner"],
                    "hlos_read": bool(permissions["hlos_present_in_read_mask"]),
                    "hlos_write": bool(permissions["hlos_present_in_write_mask"]),
                }
            )
    return {
        "query_range": f"0x{lo:x}..0x{hi:x}",
        "covered": bool(hits),
        "covering_region_count": len(hits),
        "covering_regions": hits,
    }


def reduce_branch(regions: Sequence[Mapping]) -> dict:
    starts = [r["start"] for r in regions]
    ends = [r["end_exclusive"] for r in regions]
    return {
        "regions_decoded": len(regions),
        "lowest_start": f"0x{min(starts):x}" if starts else None,
        "highest_end_exclusive": f"0x{max(ends):x}" if ends else None,
        "distinct_instances": len({r["instance"] for r in regions}),
    }


def build(tz_path: Path) -> dict:
    manifest_raw = load_pinned(POLICY_MANIFEST, POLICY_MANIFEST_SHA256)
    manifest = json.loads(manifest_raw)
    tz_data = load_pinned(tz_path, TZ_SHA256, TZ_SIZE)
    segments = parse_elf64_load_segments(tz_data)

    branches = {}
    for branch, descriptors in instance_descriptors(manifest).items():
        mpu = [d for d in descriptors if is_mpu_class(d["name"])]
        declared_mpu = sum(d["region_count"] for d in mpu)
        regions, unused, not_decoded = walk_branch(tz_data, segments, descriptors)

        # Every declared MPU slot must be accounted for exactly once.
        if len(regions) + len(unused) != declared_mpu:
            raise CoverageError(
                f"{branch}: {len(regions)} decoded + {len(unused)} unused slots "
                f"!= {declared_mpu} declared MPU regions"
            )

        queries = {
            name: answer_query(regions, lo, hi) for name, (lo, hi) in QUERIES.items()
        }
        if not queries[CONTROL_QUERY]["covered"]:
            raise CoverageError(
                f"{branch}: control query {CONTROL_QUERY} found no covering region; "
                "the walk does not reproduce the retained Verification 009 result"
            )

        branches[branch] = {
            "mpu_instances": len(mpu),
            "mpu_regions_declared": declared_mpu,
            "unused_slots": len(unused),
            "not_decoded": {
                "instances": len(not_decoded),
                "regions_declared": sum(n["region_count"] for n in not_decoded),
                "reason": "non-MPU region record layout is UNKNOWN",
                "instance_names": sorted(n["instance"] for n in not_decoded),
            },
            **reduce_branch(regions),
            "queries": queries,
        }

    agreement = {
        name: sorted({branch["queries"][name]["covered"] for branch in branches.values()})
        for name in QUERIES
    }

    return {
        "schema": SCHEMA,
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "inputs": {
            "trustzone": {
                "filename": tz_path.name,
                "sha256": TZ_SHA256,
                "size": TZ_SIZE,
                "pin_verified": True,
            },
            "policy_manifest": {
                "filename": POLICY_MANIFEST.name,
                "sha256": POLICY_MANIFEST_SHA256,
                "pin_verified": True,
            },
        },
        "prior_extraction_scope": {
            "regions_decoded_by_verification_009": 5,
            "note": (
                "Verification 009 decoded the critical region and its qhs_llcc "
                "neighbours only.  Absence-of-address claims made against that "
                "manifest were bounded by extraction scope, not by policy."
            ),
        },
        "branches": branches,
        "branch_agreement": agreement,
        "control_query": CONTROL_QUERY,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tz",
        type=Path,
        default=REPO_ROOT
        / "evidence/private/004-live-firmware-readonly-20260825-01/tz--sdd5.bin",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    result = build(args.tz)
    if args.output:
        write_new(args.output, json_bytes(result), 0o644)
        print(args.output)
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
