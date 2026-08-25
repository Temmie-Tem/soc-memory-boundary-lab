#!/usr/bin/env python3
"""Map exact TZ XPU policy coverage of the SM8150 SHRM snapshot workspace.

This is a host-only parser. It reads the SHA-256-pinned A90 TrustZone image,
does not contact the device, and emits no firmware bytes. The target is fixed
to the section-16 workspace at physical 0x09065100..0x09065fff.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
from pathlib import Path
from typing import Mapping, Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools.sm8150_xpu_policy_inventory import (
        POLICY_TABLES,
        PINS,
        decode_mpu_region_permissions,
        parse_mpu_regions,
        parse_policy_descriptors,
        parse_xpu_registry,
        verify_pinned_bytes,
    )
    from tools.xbl_dcb_inventory import parse_elf64_load_segments
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from sm8150_xpu_policy_inventory import (
        POLICY_TABLES,
        PINS,
        decode_mpu_region_permissions,
        parse_mpu_regions,
        parse_policy_descriptors,
        parse_xpu_registry,
        verify_pinned_bytes,
    )
    from xbl_dcb_inventory import parse_elf64_load_segments


SHRM_WORKSPACE_START = 0x09065100
SHRM_WORKSPACE_SIZE = 0xF00
SHRM_WORKSPACE_END_EXCLUSIVE = SHRM_WORKSPACE_START + SHRM_WORKSPACE_SIZE

EXPECTED_COVERING_XPUS = {
    "DC_NOC_NON_BROADCAST_MPU",
    "MEMNOC_MS_MPU",
    "CNOC_SNOC_MS_MPU",
}
EXPECTED_SHRM_REGION = {
    "flags": 0x9,
    "read_vmid": 0x40000000,
    "write_vmid": 0,
    "start": 0x09060000,
    "end_exclusive": 0x09070000,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def region_covers_workspace(region: Mapping[str, int]) -> bool:
    return (
        int(region["start"]) <= SHRM_WORKSPACE_START
        and SHRM_WORKSPACE_END_EXCLUSIVE <= int(region["end_exclusive"])
    )


def validate_branch_matches(
    label: str, matches: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    names = {str(match["xpu_name"]) for match in matches}
    if names != EXPECTED_COVERING_XPUS:
        raise ValueError(
            f"{label} covering XPUs {sorted(names)!r} != "
            f"{sorted(EXPECTED_COVERING_XPUS)!r}"
        )
    for match in matches:
        region = match["region"]
        permissions = match["permissions"]
        if not isinstance(region, Mapping) or not isinstance(permissions, Mapping):
            raise ValueError(f"{label} match has malformed region/permissions")
        if not region_covers_workspace(region):
            raise ValueError(f"{label} region does not cover the complete workspace")
        if permissions["hlos_present_in_read_mask"]:
            raise ValueError(f"{label} unexpectedly grants HLOS read")
        if permissions["hlos_present_in_write_mask"]:
            raise ValueError(f"{label} unexpectedly grants HLOS write")

    shrm = next(
        match
        for match in matches
        if match["xpu_name"] == "DC_NOC_NON_BROADCAST_MPU"
    )
    shrm_region = shrm["region"]
    assert isinstance(shrm_region, Mapping)
    for key, expected in EXPECTED_SHRM_REGION.items():
        if int(shrm_region[key]) != expected:
            raise ValueError(
                f"{label} SHRM region {key}={shrm_region[key]!r} != 0x{expected:x}"
            )
    return {
        "label": label,
        "covering_xpu_names": sorted(names),
        "covering_xpu_count": len(matches),
        "all_cover_complete_workspace": True,
        "all_exclude_hlos_read": True,
        "all_exclude_hlos_write": True,
        "matches": list(matches),
    }


def _format_descriptor(
    descriptor: Mapping[str, int], name: str
) -> dict[str, object]:
    return {
        "index": int(descriptor["index"]),
        "name": name,
        "resource_id": f"0x{int(descriptor['resource_id']):x}",
        "configuration_base": f"0x{int(descriptor['base']):08x}",
        "flags": f"0x{int(descriptor['flags']):x}",
        "region_count": int(descriptor["region_count"]),
    }


def _format_region(region: Mapping[str, int]) -> dict[str, object]:
    start = int(region["start"])
    end = int(region["end_exclusive"])
    return {
        "ordinal": int(region["ordinal"]),
        "index": int(region["index"]),
        "flags": int(region["flags"]),
        "read_vmid": int(region["read_vmid"]),
        "write_vmid": int(region["write_vmid"]),
        "start": start,
        "end_exclusive": end,
        "size": end - start,
    }


def analyze(tz_data: bytes) -> dict[str, object]:
    verify_pinned_bytes("trustzone", tz_data, PINS["trustzone"])
    segments = parse_elf64_load_segments(tz_data)
    registry = {
        int(record["resource_id"]): record
        for record in parse_xpu_registry(tz_data, segments)
    }

    branches: list[dict[str, object]] = []
    for label, specification in POLICY_TABLES.items():
        descriptors = parse_policy_descriptors(
            tz_data,
            segments,
            int(specification["table_vaddr"]),
            int(specification["expected_count"]),
        )
        matches: list[dict[str, object]] = []
        for descriptor in descriptors:
            name = str(registry[int(descriptor["resource_id"])]["name"])
            regions = parse_mpu_regions(
                tz_data,
                segments,
                int(descriptor["region_vaddr"]),
                int(descriptor["region_count"]),
            )
            for region in regions:
                if not region_covers_workspace(region):
                    continue
                permissions = decode_mpu_region_permissions(region)
                matches.append(
                    {
                        "xpu_name": name,
                        "descriptor": _format_descriptor(descriptor, name),
                        "region": _format_region(region),
                        "permissions": permissions,
                    }
                )
        branches.append(validate_branch_matches(label, matches))

    return {
        "workspace": {
            "start": f"0x{SHRM_WORKSPACE_START:08x}",
            "end_exclusive": f"0x{SHRM_WORKSPACE_END_EXCLUSIVE:08x}",
            "size": SHRM_WORKSPACE_SIZE,
            "role": "section-16 register snapshot workspace",
        },
        "policy_branches": branches,
        "claims": {
            "PROVED": [
                "Both exact TZ selector branches place the complete SHRM section-16 workspace inside three enabled TZ-owned XPU regions.",
                "DC_NOC_NON_BROADCAST_MPU region 5 exactly covers 0x09060000..0x0906ffff and contains 0x09065100..0x09065fff.",
                "All six branch/region matches exclude the comparative HLOS VMID from read and write masks.",
            ],
            "SUPPORTED": [
                "A Normal-World EL1 read of the SHRM snapshot workspace is expected to be denied by active XPU policy or its downstream fabric response.",
            ],
            "REFUTED": [
                "The SHRM snapshot workspace is statically unprotected or explicitly granted to ordinary HLOS in either embedded policy branch.",
            ],
            "UNKNOWN": [
                "Final runtime XPU register state and the exact fault/reset response to one EL1 read of 0x09065100.",
                "Whether a secure-world diagnostic interface can export the staged words without granting HLOS direct access.",
            ],
        },
        "classification": "CLASS_A_B_CANDIDATE_SHRM_SNAPSHOT_NO_HLOS_STATIC_GRANT",
    }


def atomic_replace(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(temporary)
    write_new(temporary, data, mode)
    os.replace(temporary, path)


def inventory(
    tz_path: Path, private_output: Path
) -> tuple[dict[str, object], dict[str, object]]:
    tz_data = tz_path.read_bytes()
    pin = verify_pinned_bytes("trustzone", tz_data, PINS["trustzone"])
    common = {
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "input": {"filename": tz_path.name, **pin},
        **analyze(tz_data),
    }
    private = {
        "schema": "sdm855-shrm-snapshot-boundary-private-v1",
        "input_path": str(tz_path.resolve()),
        **copy.deepcopy(common),
    }
    public = {
        "schema": "sdm855-shrm-snapshot-boundary-public-v1",
        **copy.deepcopy(common),
    }
    return private, public


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    firmware = root / "evidence/private/004-live-firmware-readonly-20260825-01"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tz", type=Path, default=firmware / "tz--sdd5.bin")
    parser.add_argument(
        "--private-output",
        type=Path,
        default=root / "evidence/private/013-shrm-snapshot-boundary-20260825-01.json",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=root / "evidence/manifests/013-shrm-snapshot-boundary-20260825-01.manifest.json",
    )
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    private_output = args.private_output.resolve()
    manifest_output = args.manifest_output.resolve()
    if not args.replace:
        for output in (private_output, manifest_output):
            if output.exists():
                raise FileExistsError(output)
    private, public = inventory(args.tz.resolve(), private_output)
    private_encoded = json_bytes(private)
    public["private_record"] = {
        "filename": private_output.name,
        "size": len(private_encoded),
        "sha256": sha256(private_encoded),
        "git_ignored": True,
    }
    manifest_encoded = json_bytes(public)
    if args.replace:
        atomic_replace(private_output, private_encoded, 0o600)
        atomic_replace(manifest_output, manifest_encoded, 0o644)
    else:
        write_new(private_output, private_encoded, 0o600)
        write_new(manifest_output, manifest_encoded, 0o644)
    print(private_output)
    print(manifest_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
