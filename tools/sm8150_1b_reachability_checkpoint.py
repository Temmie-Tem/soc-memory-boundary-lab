#!/usr/bin/env python3
"""Build the bounded known-aperture reachability checkpoint for 1b.

This is a host-only reconciliation of already-public, hash-pinned evidence.
It verifies that the eight known qhs_llcc-remapper/BIMC candidates are covered
by both broad TrustZone-owned raw policy ranges, and retains the separate
fixed-EL1 watchdog and ``/dev`` read-failure observations.  Legacy bit-3 HLOS
labels are preserved as source fields but are not treated as a discriminating
access verdict.  The effective initiator/path, refusing agent, global
Normal-World reachability, final runtime register state, and alternate
apertures remain unresolved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]

MEMORY_MAP_NAME = "MEMORY_MAP.md"
MEMORY_MAP_SIZE = 10_718
MEMORY_MAP_SHA256 = "af44a5e7cf3afd2fa8bd3b75c9ab9f6c6f5edefdabb47f552eeafc08ffbc0108"

POLICY_009_NAME = "009-xpu-policy-inventory-20260825-01.manifest.json"
POLICY_009_SIZE = 60_193
POLICY_009_SHA256 = "f5c661af73cd6b4a0d423ef44a59b11cba0e208ad178670ff2dabf097bf2e4e6"

INITIALIZER_010_NAME = "010-xpu-initializer-inventory-20260825-01.manifest.json"
INITIALIZER_010_SIZE = 41_566
INITIALIZER_010_SHA256 = "baeef82f8f0fad7c7e897e3c373dacd129b7f2ed22d78c075a94141ee36c1ce2"

WATCHDOG_007_NAME = "007-inline-remapper-read-watchdog-20260825-01.manifest.json"
WATCHDOG_007_SIZE = 2_900
WATCHDOG_007_SHA256 = "50d0e324f4356c4ba12c848d86e9563d1f82cfc789981516e05c901dd8d4bb82"

DEVMEM_005_NAME = "005-icb-remapper-control-node-20260825-01.manifest.json"
DEVMEM_005_SIZE = 1_819
DEVMEM_005_SHA256 = "35e96ea34bb2d2fea643edcd408710e44c6a936d7ef395859db119d0fa5d31e3"

SCHEMA = "sm8150-1b-known-aperture-reachability-checkpoint-v2"
EXPERIMENT_ID = "1b-known-aperture-reachability-checkpoint"
MODE = "HOST_ONLY_READ_ONLY"

BROAD_PROTECTORS = ("MEMNOC_MS_MPU", "CNOC_SNOC_MS_MPU")
KNOWN_CANDIDATES = (
    {"instance": 0, "remapper": "0x09248080", "bimc_mpu": "0x0924e000", "bimc_resource_id": "0x2e"},
    {"instance": 1, "remapper": "0x092c8080", "bimc_mpu": "0x092ce000", "bimc_resource_id": "0x2f"},
    {"instance": 2, "remapper": "0x09348080", "bimc_mpu": "0x0934e000", "bimc_resource_id": "0x3f"},
    {"instance": 3, "remapper": "0x093c8080", "bimc_mpu": "0x093ce000", "bimc_resource_id": "0x40"},
)
KNOWN_ADDRESSES = frozenset(
    value
    for candidate in KNOWN_CANDIDATES
    for value in (candidate["remapper"], candidate["bimc_mpu"])
)

_MEMORY_MAP_ROWS = (
    ("0x00000000–0x0fffffff", "MEMNOC_MS_MPU", "enabled/TZ-owned", "Raw client-vector meaning"),
    ("0x09000000–0x097fffff", "CNOC_SNOC_MS_MPU", "enabled/TZ-owned", "second overlapping record"),
    ("0x09248000–0x09248fff", "DC_NOC_BROADCAST_MPU", "raw read word", "effective live path"),
    ("0x09248080–0x092480d8", "qhs_llcc remapper instance 0", "PROVED", "watchdog"),
    ("0x0924e000", "BIMC_MPU0", "PROVED", "raw policy coverage"),
    ("0x092c8080–0x092c80d8", "qhs_llcc remapper instance 1", "PROVED", "raw policy coverage"),
    ("0x092ce000", "BIMC_MPU1", "PROVED", "raw policy coverage"),
    ("0x09348080–0x093480d8", "qhs_llcc remapper instance 2", "PROVED", "raw policy coverage"),
    ("0x0934e000", "BIMC_MPU2", "PROVED", "raw policy coverage"),
    ("0x093c8080–0x093c80d8", "qhs_llcc remapper instance 3", "PROVED", "raw policy coverage"),
    ("0x093ce000", "BIMC_MPU3", "PROVED", "raw policy coverage"),
)


class ReachabilityError(ValueError):
    """Raised when a pinned source or bounded checkpoint invariant fails."""


TraceError = ReachabilityError


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_pinned(path: Path, expected_size: int, expected_sha256: str, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReachabilityError(f"cannot open exact {label}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise ReachabilityError(f"exact {label} size/type mismatch")
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise ReachabilityError(f"exact {label} truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ReachabilityError(f"exact {label} changed during read")
        payload = b"".join(chunks)
        if len(payload) != expected_size:
            raise ReachabilityError(f"exact {label} size changed during read")
    finally:
        os.close(fd)
    digest = _sha256(payload)
    if digest != expected_sha256:
        raise ReachabilityError(f"exact {label} SHA-256 mismatch")
    return payload


def _parse_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ReachabilityError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ReachabilityError(f"{label} root is not an object")
    return value


def _parse_memory_map(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReachabilityError("MEMORY_MAP is not strict UTF-8") from exc
    if "## Boot-time SHRM and remapper landmarks" not in text:
        raise ReachabilityError("MEMORY_MAP landmark heading changed")
    rows: list[dict[str, str]] = []
    lines = text.splitlines()
    for address, name, required_a, required_b in _MEMORY_MAP_ROWS:
        matches = []
        for line in lines:
            cells = [cell.strip().strip("`") for cell in line.split("|")[1:-1]]
            if len(cells) >= 3 and cells[0] == address and (cells[1] == name or cells[1].startswith(f"{name}`")):
                matches.append(line)
        if len(matches) != 1:
            raise ReachabilityError(f"MEMORY_MAP row changed for {address} {name}")
        line = matches[0]
        if required_a not in line or required_b not in line:
            raise ReachabilityError(f"MEMORY_MAP semantics changed for {address} {name}")
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if len(cells) < 3:
            raise ReachabilityError(f"MEMORY_MAP table row malformed for {address}")
        rows.append({"address": address, "name": name, "status": cells[2]})
    return {
        "landmark_heading": "Boot-time SHRM and remapper landmarks",
        "required_row_count": len(rows),
        "rows": rows,
        "source_scope": "PUBLIC_MEMORY_MAP_SEMANTIC_ANCHORS_ONLY",
    }


def _parse_policy_009(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema") != "sdm855-xpu-policy-inventory-public-v1":
        raise ReachabilityError("009 schema changed")
    if manifest.get("device_access") is not False:
        raise ReachabilityError("009 device-access boundary changed")
    critical = manifest.get("critical_policy_result")
    tables = manifest.get("policy_tables")
    tested = manifest.get("tested_access")
    if not isinstance(critical, dict) or not isinstance(tables, dict) or not isinstance(tested, dict):
        raise ReachabilityError("009 policy fields are malformed")
    if tested.get("physical_address") != "0x09248080":
        raise ReachabilityError("009 tested address changed")
    if critical.get("tested_address_covered") is not True or critical.get("selector_branch_invariant") is not True:
        raise ReachabilityError("009 critical coverage invariant changed")
    if (
        critical.get("hlos_granted_by_static_record") is not False
        or critical.get("exact_constructed_client_permission_bytes") != ["0x11", "0x08"]
    ):
        raise ReachabilityError("009 legacy decode fields changed")
    branch_summary: dict[str, Any] = {}
    for branch in ("selector_result_ge_2", "selector_result_lt_2"):
        table = tables.get(branch)
        if not isinstance(table, dict):
            raise ReachabilityError(f"009 missing selector branch {branch}")
        region = table.get("critical_region")
        decode = table.get("critical_permission_decode")
        if not isinstance(region, dict) or not isinstance(decode, dict):
            raise ReachabilityError(f"009 malformed critical region/decode {branch}")
        if (
            region.get("start") != "0x09248000"
            or region.get("end_exclusive") != "0x09249000"
            or region.get("index") != 11
            or region.get("owner") is not None and region.get("owner") != "TZ"
            or region.get("read_vmid") != "0x80000000"
            or region.get("write_vmid") != "0x00000000"
        ):
            raise ReachabilityError(f"009 critical region changed {branch}")
        if (
            decode.get("owner") != "TZ"
            or decode.get("hlos_present_in_read_mask") is not False
            or decode.get("hlos_present_in_write_mask") is not False
            or decode.get("standard_vmid_read_bits") != "0x00000000"
            or decode.get("standard_vmid_write_bits") != "0x00000000"
            or decode.get("client_permission_bytes") != ["0x11", "0x08"]
            or decode.get("client_permission_fields") != {
                "nonsecure_client_ro_vector": 2,
                "nonsecure_client_wo_vector": 0,
                "secure_client_ro_vector": 1,
                "secure_client_wo_vector": 1,
            }
        ):
            raise ReachabilityError(f"009 permission decode changed {branch}")
        branch_summary[branch] = {
            "critical_region": {
                "start": region["start"],
                "end_exclusive": region["end_exclusive"],
                "index": region["index"],
            },
            "owner": decode["owner"],
            "raw_read_vmid": region["read_vmid"],
            "raw_write_vmid": region["write_vmid"],
            "legacy_bit3_read_marker": decode["hlos_present_in_read_mask"],
            "legacy_bit3_write_marker": decode["hlos_present_in_write_mask"],
            "standard_vmid_read_bits": decode["standard_vmid_read_bits"],
            "standard_vmid_write_bits": decode["standard_vmid_write_bits"],
            "derived_client_permission_bytes": decode["client_permission_bytes"],
            "derived_client_permission_fields": decode["client_permission_fields"],
            "legacy_formatter_narrative": decode.get("static_policy_interpretation", "REDACTED"),
            "effective_actor_and_path": "UNKNOWN",
        }
    return {
        "schema": manifest["schema"],
        "tested_address": tested["physical_address"],
        "selector_branch_invariant": True,
        "tested_address_covered": True,
        "legacy_static_hlos_grant_field": False,
        "bit3_predicate_discriminating": False,
        "effective_hlos_access": "UNKNOWN",
        "branches": branch_summary,
    }


def _validate_hit(
    hit: Any,
    resource: str,
    start: str,
    end: str,
    read_vmid: str,
    write_vmid: str,
) -> None:
    if not isinstance(hit, dict):
        raise ReachabilityError("010 policy hit is malformed")
    if (
        hit.get("resource") != resource
        or hit.get("start") != start
        or hit.get("end_exclusive") != end
        or hit.get("owner") != "TZ"
        or hit.get("hlos_read") is not False
        or hit.get("hlos_write") is not False
        or hit.get("read_vmid") != read_vmid
        or hit.get("write_vmid") != write_vmid
    ):
        raise ReachabilityError(f"010 policy hit changed for {resource}")


def _parse_initializer_010(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema") != "sdm855-xpu-initializer-inventory-public-v1":
        raise ReachabilityError("010 schema changed")
    if manifest.get("device_access") is not False:
        raise ReachabilityError("010 device-access boundary changed")
    policy = manifest.get("controller_aperture_policy")
    if not isinstance(policy, dict):
        raise ReachabilityError("010 controller policy is malformed")
    if policy.get("branch_invariant_broad_coverage") is not True or policy.get("broad_protectors") != list(BROAD_PROTECTORS):
        raise ReachabilityError("010 broad policy invariant changed")
    if policy.get("static_hlos_grant") is not False:
        raise ReachabilityError("010 legacy static-HLOS field changed")
    branches = policy.get("selector_branches")
    if not isinstance(branches, dict):
        raise ReachabilityError("010 selector branches are malformed")
    expected_addresses = sorted(KNOWN_ADDRESSES)
    branch_summary: dict[str, Any] = {}
    for branch in ("selector_result_ge_2", "selector_result_lt_2"):
        record = branches.get(branch)
        if not isinstance(record, dict) or not isinstance(record.get("addresses"), list):
            raise ReachabilityError(f"010 missing address list {branch}")
        addresses = record["addresses"]
        if any(not isinstance(item, dict) for item in addresses):
            raise ReachabilityError(f"010 address row malformed {branch}")
        actual_addresses = sorted(item.get("address") for item in addresses)
        if any(not isinstance(address, str) for address in actual_addresses):
            raise ReachabilityError(f"010 address type changed {branch}")
        if len(addresses) != 8 or actual_addresses != expected_addresses or len(set(actual_addresses)) != 8:
            raise ReachabilityError(f"010 address cardinality/set changed {branch}")
        by_address: dict[str, dict[str, Any]] = {}
        for item in addresses:
            address = item["address"]
            hits = item.get("hits")
            if not isinstance(hits, list):
                raise ReachabilityError(f"010 hits malformed at {address}")
            broad_hits = {}
            for hit in hits:
                if isinstance(hit, dict) and hit.get("resource") in BROAD_PROTECTORS:
                    broad_hits[hit["resource"]] = hit
            if set(broad_hits) != set(BROAD_PROTECTORS):
                raise ReachabilityError(f"010 broad protectors missing at {address}")
            _validate_hit(
                broad_hits["MEMNOC_MS_MPU"],
                "MEMNOC_MS_MPU",
                "0x00000000",
                "0x10000000",
                "0x80000000",
                "0x80000000",
            )
            _validate_hit(
                broad_hits["CNOC_SNOC_MS_MPU"],
                "CNOC_SNOC_MS_MPU",
                "0x09000000",
                "0x09800000",
                "0xf0000000",
                "0xf0000000",
            )
            if address == "0x09248080":
                dc_hits = [hit for hit in hits if isinstance(hit, dict) and hit.get("resource") == "DC_NOC_BROADCAST_MPU"]
                if len(dc_hits) != 1:
                    raise ReachabilityError("010 tested DC_NOC region missing or duplicated")
                _validate_hit(
                    dc_hits[0],
                    "DC_NOC_BROADCAST_MPU",
                    "0x09248000",
                    "0x09249000",
                    "0x80000000",
                    "0x00000000",
                )
            by_address[address] = {
                "address": address,
                "broad_protectors": list(BROAD_PROTECTORS),
                "tz_owned": True,
                "legacy_bit3_read_marker": False,
                "legacy_bit3_write_marker": False,
                "raw_policy_rows": [
                    {
                        "resource": resource,
                        "start": broad_hits[resource]["start"],
                        "end_exclusive": broad_hits[resource]["end_exclusive"],
                        "owner": broad_hits[resource]["owner"],
                        "read_vmid": broad_hits[resource]["read_vmid"],
                        "write_vmid": broad_hits[resource]["write_vmid"],
                    }
                    for resource in BROAD_PROTECTORS
                ],
                "effective_hlos_access": "UNKNOWN",
            }
        branch_summary[branch] = {
            "selector_predicate": record.get("selector_predicate", "REDACTED"),
            "address_count": len(by_address),
            "addresses": [by_address[address] for address in expected_addresses],
        }
    instances = policy.get("instances")
    if not isinstance(instances, list) or len(instances) != 4:
        raise ReachabilityError("010 instance list changed")
    expected_instances = [
        {"instance": c["instance"], "remapper": c["remapper"], "bimc_mpu": c["bimc_mpu"], "bimc_resource_id": c["bimc_resource_id"]}
        for c in KNOWN_CANDIDATES
    ]
    if instances != expected_instances:
        raise ReachabilityError("010 remapper/BIMC instance mapping changed")
    return {
        "schema": manifest["schema"],
        "branch_invariant_broad_coverage": True,
        "broad_protectors": list(BROAD_PROTECTORS),
        "known_candidate_count": 8,
        "instances": expected_instances,
        "selector_branches": branch_summary,
        "runtime_register_readback": policy.get("runtime_register_readback", "UNKNOWN"),
    }


def _parse_watchdog_007(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema") != "sdm855-a90-inline-remapper-read-watchdog-manifest-v1":
        raise ReachabilityError("007 schema changed")
    read = manifest.get("read")
    reset = manifest.get("reset_evidence")
    if manifest.get("status") != "FIXED_READ_FOLLOWED_BY_NON_SECURE_WATCHDOG" or not isinstance(read, dict) or not isinstance(reset, dict):
        raise ReachabilityError("007 watchdog status changed")
    if (
        read.get("fixed_physical_base") != "0x09248080"
        or read.get("operation_count") != 1
        or read.get("arbitrary_address_input") is not False
        or read.get("memory_or_mmio_writes") is not False
        or read.get("probe_outcome") != "PROBE_FAILED"
        or read.get("value_observed") is not None
        or reset.get("bootloader_upload_cause") != "Non Secure Watchdog Bark"
        or reset.get("reset_type") != "warm reset"
    ):
        raise ReachabilityError("007 fixed-EL1 watchdog evidence changed")
    return {
        "fixed_address": read["fixed_physical_base"],
        "operation_count": read["operation_count"],
        "value_observed": None,
        "probe_outcome": read["probe_outcome"],
        "watchdog_cause": reset["bootloader_upload_cause"],
        "reset_type": reset["reset_type"],
        "memory_or_mmio_writes": False,
    }


def _parse_devmem_005(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema") != "sdm855-a90-icb-remapper-readonly-manifest-v1":
        raise ReachabilityError("005 schema changed")
    failure = manifest.get("read_failure")
    temporary = manifest.get("temporary_devfs_node")
    if manifest.get("outcome") != "READ_FAILED" or not isinstance(failure, dict) or not isinstance(temporary, dict):
        raise ReachabilityError("005 read-failure status changed")
    if (
        failure.get("address") != "0x09248080"
        or failure.get("base") != "0x09248080"
        or failure.get("offset") != "0x00"
        or failure.get("width_bits") != 32
        or failure.get("status") != "error"
        or failure.get("rc") != 1
        or manifest.get("register_read_attempt_count") != 1
        or manifest.get("register_read_success_count") != 0
        or manifest.get("memory_or_mmio_writes") is not False
        or any(temporary.get(key) != "ok" for key in ("preclean_status", "create_status", "absent_check_status", "cleanup_status"))
    ):
        raise ReachabilityError("005 read-failure evidence changed")
    return {
        "fixed_address": failure["address"],
        "offset": failure["offset"],
        "width_bits": failure["width_bits"],
        "read_attempt_count": 1,
        "read_success_count": 0,
        "failure_status": failure["status"],
        "rc": failure["rc"],
        "memory_or_mmio_writes": False,
        "temporary_node_lifecycle": "PREclean_CREATE_ABSENT_CHECK_CLEANUP_ALL_OK",
    }


def _record(name: str, size: int, digest: str) -> dict[str, Any]:
    return {"filename": name, "size": size, "sha256": digest}


def build_manifest(repository_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Read and reconcile only the five exact public inputs."""

    paths = {
        "memory_map": repository_root / "docs" / MEMORY_MAP_NAME,
        "policy_009": repository_root / "evidence/manifests" / POLICY_009_NAME,
        "initializer_010": repository_root / "evidence/manifests" / INITIALIZER_010_NAME,
        "watchdog_007": repository_root / "evidence/manifests" / WATCHDOG_007_NAME,
        "devmem_005": repository_root / "evidence/manifests" / DEVMEM_005_NAME,
    }
    memory_map_payload = _read_pinned(paths["memory_map"], MEMORY_MAP_SIZE, MEMORY_MAP_SHA256, "MEMORY_MAP")
    policy_payload = _read_pinned(paths["policy_009"], POLICY_009_SIZE, POLICY_009_SHA256, "009 policy manifest")
    initializer_payload = _read_pinned(paths["initializer_010"], INITIALIZER_010_SIZE, INITIALIZER_010_SHA256, "010 initializer manifest")
    watchdog_payload = _read_pinned(paths["watchdog_007"], WATCHDOG_007_SIZE, WATCHDOG_007_SHA256, "007 watchdog manifest")
    devmem_payload = _read_pinned(paths["devmem_005"], DEVMEM_005_SIZE, DEVMEM_005_SHA256, "005 control-node manifest")
    memory_map = _parse_memory_map(memory_map_payload)
    policy = _parse_policy_009(_parse_json(policy_payload, "009 policy manifest"))
    initializer = _parse_initializer_010(_parse_json(initializer_payload, "010 initializer manifest"))
    watchdog = _parse_watchdog_007(_parse_json(watchdog_payload, "007 watchdog manifest"))
    devmem = _parse_devmem_005(_parse_json(devmem_payload, "005 control-node manifest"))
    if initializer["known_candidate_count"] != 8:
        raise ReachabilityError("known candidate cardinality changed")
    if watchdog["fixed_address"] != devmem["fixed_address"] or watchdog["fixed_address"] != policy["tested_address"]:
        raise ReachabilityError("fixed tested aperture identity diverged")
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {
            "memory_map": _record(MEMORY_MAP_NAME, MEMORY_MAP_SIZE, MEMORY_MAP_SHA256),
            "policy_009": _record(POLICY_009_NAME, POLICY_009_SIZE, POLICY_009_SHA256),
            "initializer_010": _record(INITIALIZER_010_NAME, INITIALIZER_010_SIZE, INITIALIZER_010_SHA256),
            "watchdog_007": _record(WATCHDOG_007_NAME, WATCHDOG_007_SIZE, WATCHDOG_007_SHA256),
            "devmem_005": _record(DEVMEM_005_NAME, DEVMEM_005_SIZE, DEVMEM_005_SHA256),
        },
        "known_apertures": {
            "candidate_count": 8,
            "candidates": [
                {"instance": candidate["instance"], "kind": kind, "address": candidate[field]}
                for candidate in KNOWN_CANDIDATES
                for kind, field in (("remapper", "remapper"), ("bimc_mpu", "bimc_mpu"))
            ],
            "instances": initializer["instances"],
            "broad_protectors": initializer["broad_protectors"],
            "selector_branches": initializer["selector_branches"],
            "all_branches_cover_all_candidates": True,
            "all_hits_tz_owned": True,
            "all_hits_legacy_bit3_clear_read": True,
            "all_hits_legacy_bit3_clear_write": True,
            "bit3_predicate_discriminating": False,
            "effective_hlos_access": "UNKNOWN",
            "policy_009_tested_dc_noc": policy,
            "memory_map_anchors": memory_map,
        },
        "reachability": {
            "known_aperture_policy": "PROVED_BROAD_TZ_OWNED_RAW_STATIC_COVERAGE",
            "fixed_el1_watchdog": watchdog,
            "devmem_route": devmem,
            "direct_instance_0_nonreturn": "CONFIRMED",
            "known_aperture_normal_world_reachability": "UNDECIDABLE_FROM_STATIC_POLICY_AND_NONRETURN",
            "refusing_agent": "UNDECIDABLE",
            "global_normal_world_reachability": "UNKNOWN",
            "alternate_apertures": "UNKNOWN",
            "final_runtime_register_state": "UNKNOWN",
            "status": "BOUNDED_1B_CHECKPOINT_NOT_GLOBAL_REACHABILITY_PROOF",
        },
        "scope": {
            "model": "EIGHT_KNOWN_QHS_LLCC_REMAP_AND_BIMC_APERTURES_ONLY",
            "policy_branches": 2,
            "broad_policy_coverage": True,
            "tz_ownership": True,
            "legacy_bit3_marker": False,
            "bit3_predicate_discriminating": False,
            "effective_hlos_access": "UNKNOWN",
            "fixed_el1_watchdog_is_causal": "UNKNOWN",
            "refusing_agent": "UNDECIDABLE",
            "global_reachability": "UNKNOWN",
            "runtime_register_readback": "UNKNOWN",
            "alternate_apertures": "UNKNOWN",
            "no_device_contact": True,
            "no_write": True,
        },
        "claims": {
            "PROVED": [
                "The five public source artifacts are bound by regular-file, O_NOFOLLOW, size, content-stability, and SHA-256 checks.",
                "Both exact 010 selector branches enumerate the same eight known qhs_llcc-remapper/BIMC candidate addresses.",
                "Every known candidate has MEMNOC_MS_MPU and CNOC_SNOC_MS_MPU hits whose exact TZ owner fields and raw permission words are retained.",
                "The exact 009 policy evidence covers the tested 0x09248080 DC_NOC_BROADCAST_MPU region in both selector branches, retains raw words and standard-VMID fields, and labels the client-permission values as decoder-derived.",
                "The retained 007 fixed EL1 read produced no value and is followed by a recorded Non Secure Watchdog Bark, while the 005 control-node route failed before a read and recorded no write.",
            ],
            "SUPPORTED": [],
            "HYPOTHESIS": [],
            "REFUTED": [
                "A false result from the retained bit-3 HLOS predicate is sufficient to identify an effective HLOS denial."
            ],
            "UNKNOWN": [
                "Effective initiator/client access, overlap and instance selection, the refusing agent, global Normal-World reachability, alternate apertures, final runtime policy/register values, watchdog causality, enforcement ordering relative to the final DRAM transform, and any alias or bypass."
            ],
        },
        "boundary_bypass": {
            "status": "NOT_AUTHORIZED",
            "device": "none",
            "smc": "none",
            "mmio": "none",
            "protected_memory": "none",
            "reason": "Host-only public-evidence reconciliation; no activation, read, or write was performed.",
        },
        "definition_of_done": {
            "target": {
                "binding": "PROVED_EXACT_PUBLIC_SOURCE_PINS",
                "marketing_name": "A90 5G",
                "model": "SM-A908N",
                "soc": "SM8150",
                "soc_name": "Snapdragon 855",
            },
            "build": {"status": "NOT_APPLICABLE", "reason": "Interpreted host Python; no device/kernel build."},
            "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."},
            "commands": {
                "status": "REDACTED_REPRODUCTION_TEMPLATE",
                "command": "python3 tools/sm8150_1b_reachability_checkpoint.py --output <public-manifest-path>",
                "reason": "Private paths are not published; exact public source hashes are retained.",
            },
            "repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only static reconciliation; no runtime repetitions."},
            "rollback": {"status": "NOT_APPLICABLE", "reason": "No device state."},
            "recovery": {"status": "NOT_APPLICABLE", "reason": "No device state."},
            "device_binding": {"status": "NOT_APPLICABLE", "reason": "No device contact."},
            "tool_and_build": {"tool": f"{Path(__file__).name} schema {SCHEMA}", "build": "NOT_APPLICABLE"},
        },
    }


def encode_manifest(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8")


def write_no_clobber(path: Path, payload: bytes) -> dict[str, Any]:
    if not path.parent.is_dir():
        raise ReachabilityError(f"manifest parent does not exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise ReachabilityError("manifest output already exists or is unsafe") from exc
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise ReachabilityError("manifest write made no progress")
            view = view[count:]
        os.fsync(fd)
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    return {"basename": path.name, "size_bytes": len(payload), "sha256": _sha256(payload), "mode": "0644"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        publication = write_no_clobber(args.output, encode_manifest(build_manifest()))
    except (ReachabilityError, OSError) as exc:
        print(f"1b reachability checkpoint: {exc}", file=sys.stderr)
        return 2
    print(
        f"wrote {publication['basename']} {publication['size_bytes']} bytes "
        f"sha256={publication['sha256']} mode={publication['mode']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
