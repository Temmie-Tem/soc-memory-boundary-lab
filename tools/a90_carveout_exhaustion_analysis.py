#!/usr/bin/env python3
"""Decide whether a full-size ION allocation consumes its whole carveout.

`docs/PA28_UNBLOCKED_2026-08-27.md` argued by pigeonhole that a 320 MiB
allocation from a 320 MiB carveout must start at the region base.  The 020M
review held that `UNKNOWN`, correctly: nothing had shown the allocation spans
the pool rather than the heap over-committing or the pool exceeding what the
device tree declares.

The receipt this reduces answers it directly.  With the full size held, nothing
allocatable may remain -- not one page.  A failure under hold proves nothing on
its own, so it is only admissible when bracketed by two controls: the same
probe sizes succeed before the hold and again after it is released.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

SCHEMA = "a90_heap_exhaustion_v1"
MANIFEST_SCHEMA = "a90_carveout_exhaustion_v2"
MIB = 1 << 20
MAX_RECEIPT_BYTES = 1 << 20

PROBE_SOURCE_PATH = Path(__file__).with_name("a90_heap_exhaustion_probe.c")
PROBE_SOURCE_PIN = {
    "basename": "a90_heap_exhaustion_probe.c",
    "size_bytes": 6491,
    "sha256": "02dc73f8731bcdfb6e82d8fb29df2ca73e57a51003435506a29cdd10798126f8",
}
PROBE_BINARY_METADATA = {
    "basename": "a90_heap_exhaustion_probe",
    "size_bytes": None,
    "sha256": "9361018ea2e9f9169ed8e204c259a243647700448aa31f5515f2e599a4815303",
    "status": "NOT_RETAINED",
}
CANONICAL_RAW_PIN = {
    "basename": "carveout-exhaustion.jsonl",
    "size_bytes": 2368,
    "sha256": "cb16a3c1ba64f6050a52edd2e2fefe9a405d96fde86928cfe344b74764d28694",
}
EXECUTED_COMMAND_TEMPLATE = (
    "aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror "
    "-o a90_heap_exhaustion_probe tools/a90_heap_exhaustion_probe.c; "
    "./a90_heap_exhaustion_probe <ion-node> camera_preview 320"
)
DEPENDENCY_020M_PATH = (
    Path(__file__).resolve().parents[1]
    / "evidence/manifests/verification-020m-pa28-dt-20260827-03.manifest.json"
)
DEPENDENCY_020M_PIN = {
    "basename": "verification-020m-pa28-dt-20260827-03.manifest.json",
    "size_bytes": 8246,
    "sha256": "69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a",
}

def _read_stable(path: Path, label: str) -> tuple[bytes, dict]:
    """Read a bounded regular file through a stable, symlink-refusing fd."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file")
        if before.st_size <= 0 or before.st_size > MAX_RECEIPT_BYTES:
            raise ValueError(f"{label} has invalid size {before.st_size}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise ValueError(f"{label} truncated while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    final_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity != final_identity:
        raise ValueError(f"{label} changed while being read")
    data = b"".join(chunks)
    metadata = {
        "basename": path.name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    return data, metadata


def require_metadata(actual: dict, expected: dict, label: str = "input") -> None:
    """Fail closed when a retained artifact no longer matches its pin."""
    expected_size = expected.get("size_bytes", expected.get("bytes"))
    for field in ("basename", "size_bytes", "sha256"):
        expected_value = expected_size if field == "size_bytes" else expected.get(field)
        if actual.get(field) != expected_value:
            raise ValueError(
                f"{label} {actual.get('basename')!r} {field} does not match its pin"
            )


def load_records(path: Path, expected_pin: dict | None = None) -> tuple[list[dict], dict]:
    """Read and hash the receipt through a stable regular-file descriptor."""
    data, metadata = _read_stable(path, f"receipt {path.name}")
    records = []
    for line in data.decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if record.get("schema") != SCHEMA:
            raise ValueError(f"foreign schema in {path.name}: {record.get('schema')!r}")
        records.append(record)
    if not records:
        raise ValueError(f"{path.name} holds no records")
    metadata["status"] = "RETAINED_PRIVATE_RECEIPT"
    if expected_pin is not None:
        require_metadata(metadata, expected_pin, "receipt")
    return records, metadata


def probe_source_metadata() -> dict:
    """Return the retained probe-source pin recorded by the experiment README."""
    _, metadata = _read_stable(PROBE_SOURCE_PATH, "retained probe source")
    require_metadata(metadata, PROBE_SOURCE_PIN, "retained probe source")
    metadata["status"] = "RETAINED_SOURCE"
    return metadata


def _validate_020m_semantics(data: bytes, label: str) -> dict:
    """Validate the exact DT chain imported from the pinned 020M manifest."""
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if manifest.get("schema") != "a90-pa28-dt-snapshot-v1":
        raise ValueError(f"{label} has an unexpected schema")
    if manifest.get("experiment_id") != "verification-020m-pa28-dt-20260827-03":
        raise ValueError(f"{label} has an unexpected experiment id")
    target = manifest.get("target")
    if not isinstance(target, dict) or {
        target.get("model"), target.get("soc"), target.get("version")
    } != {"SM-A908N", "SM8150", "A90 Linux init 0.9.285"}:
        raise ValueError(f"{label} target identity changed")
    bridge = manifest.get("bridge")
    if not isinstance(bridge, dict) or bridge.get("serial_device") != "/dev/ttyACM0":
        raise ValueError(f"{label} bridge device changed")
    if (bridge.get("serial_realpath") != "/dev/ttyACM0"
            or bridge.get("strict_expect_realpath_option") is not True
            or bridge.get("strict_device_glob_option") is not True):
        raise ValueError(f"{label} strict bridge binding changed")
    semantic = manifest.get("semantic")
    if not isinstance(semantic, dict):
        raise ValueError(f"{label} has no semantic DT chain")
    heap = semantic.get("ion_heap30")
    region = semantic.get("camera_mem_region")
    if not isinstance(heap, dict) or not isinstance(region, dict):
        raise ValueError(f"{label} lacks heap/region semantics")
    if (heap.get("reg"), heap.get("memory_region_phandle"), heap.get("name")) != (
            "0x1e", "0x67a", "qcom,ion-heap"):
        raise ValueError(f"{label} heap-30 semantics changed")
    reg = region.get("reg")
    optional = region.get("optional_properties")
    if (region.get("name"), region.get("phandle"),
            isinstance(reg, dict) and reg.get("base"),
            isinstance(reg, dict) and reg.get("size"),
            isinstance(reg, dict) and reg.get("end_exclusive")) != (
            "camera_mem_region", "0x67a", "0xc2000000", "0x14000000", "0xd6000000"):
        raise ValueError(f"{label} camera region semantics changed")
    if (not isinstance(optional, dict)
            or optional.get("camera_no_map", {}).get("present") is not False
            or optional.get("camera_reusable", {}).get("present") is not False
            or region.get("ion_recyclable", {}).get("present") is not True):
        raise ValueError(f"{label} optional DT property semantics changed")
    return {
        "experiment_id": manifest["experiment_id"],
        "schema": manifest["schema"],
        "target": {k: target[k] for k in ("model", "soc", "version")},
        "bridge": {
            "serial_device": bridge["serial_device"],
            "serial_realpath": bridge["serial_realpath"],
            "strict_expect_realpath_option": bridge["strict_expect_realpath_option"],
            "strict_device_glob_option": bridge["strict_device_glob_option"],
        },
        "semantic": {
            "heap30_reg": heap["reg"],
            "heap30_memory_region_phandle": heap["memory_region_phandle"],
            "camera_phandle": region["phandle"],
            "camera_base": reg["base"],
            "camera_size": reg["size"],
            "camera_end_exclusive": reg["end_exclusive"],
        },
    }


def load_020m_dependency(path: Path | None = None) -> dict:
    """Read, hash-pin and semantically validate the canonical 020M manifest."""
    path = DEPENDENCY_020M_PATH if path is None else path
    data, metadata = _read_stable(path, "020M dependency manifest")
    require_metadata(metadata, DEPENDENCY_020M_PIN, "020M dependency manifest")
    metadata["status"] = "RETAINED_PUBLIC_DEPENDENCY"
    metadata["semantic_attestation"] = _validate_020m_semantics(
        data, "020M dependency manifest"
    )
    return metadata


def _region_from_dependency(dependency: dict) -> dict:
    """Extract only the validated DT region values needed by the reduction."""
    try:
        semantic = dependency["semantic_attestation"]["semantic"]
        return {
            "node": "camera_mem_region",
            "base": int(semantic["camera_base"], 16),
            "size": int(semantic["camera_size"], 16),
            "heap_id": 30,
            "heap_name": "camera_preview",
            "memory_region_phandle": int(semantic["camera_phandle"], 16),
            "end_exclusive": int(semantic["camera_end_exclusive"], 16),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("020M dependency lacks validated DT region semantics") from exc


def provenance(input_metadata: dict, dependency: dict | None = None) -> dict:
    """Describe retained artifacts and the provenance absent from the receipt.

    The raw 021 producer emitted no target, bridge, argv or timestamp records.
    The separate 020M receipt cannot be substituted for same-run attestation.
    These fields therefore deliberately remain UNKNOWN rather than inheriting
    the current bridge or an adjacent experiment's identity.
    """
    dependency = dependency if dependency is not None else load_020m_dependency()
    return {
        "attestation_status": "INCOMPLETE_SAME_RUN_ATTESTATION",
        "raw_receipt": dict(input_metadata),
        "dependency_020m": dependency,
        "probe_source": probe_source_metadata(),
        "probe_binary": dict(PROBE_BINARY_METADATA),
        "target": {
            "status": "UNKNOWN_UNRETAINED",
            "same_run_attested": False,
            "intended_model": "SM-A908N",
            "intended_soc": "SM8150",
            "reason": (
                "021 raw receipt has no target identity or preflight record; "
                "020M is a separate collection"
            ),
        },
        "bridge": {
            "status": "UNKNOWN_UNRETAINED",
            "same_run_attested": False,
            "serial_device": "UNKNOWN_UNRETAINED",
            "serial_id": "UNKNOWN_UNRETAINED",
            "reason": "021 raw receipt has no bridge binding record",
        },
        "commands": {
            "status": "UNKNOWN_UNRETAINED",
            "same_run_attested": False,
            "argv_recorded": False,
            "executed_receipt": "NOT_RETAINED",
            "template": EXECUTED_COMMAND_TEMPLATE,
        },
        "timestamp": {"status": "UNKNOWN_UNRETAINED"},
    }


def analyse(records: list[dict], dependency: dict | None = None,
            input_metadata: dict | None = None) -> dict:
    if input_metadata is not None:
        require_metadata(input_metadata, CANONICAL_RAW_PIN, "canonical 021 receipt")
    dependency = dependency if dependency is not None else load_020m_dependency()
    dt_region = _region_from_dependency(dependency)
    context = next((r for r in records if r["type"] == "context"), None)
    if context is None:
        raise ValueError("receipt has no context record")
    if any(r["type"] == "abort" for r in records):
        reason = next(r for r in records if r["type"] == "abort").get("reason")
        return {"schema": MANIFEST_SCHEMA, "verdict": "ABORTED",
                "abort_reason": reason, "instrument_ok": False}

    phases: dict[str, list[dict]] = {}
    for record in records:
        if record["type"] == "probe":
            phases.setdefault(record["phase"], []).append(record)

    for required in ("control_before", "under_hold", "control_after"):
        if required not in phases:
            raise ValueError(f"receipt is missing phase {required}")

    sizes = [p["bytes"] for p in phases["control_before"]]
    for name, probes in phases.items():
        if [p["bytes"] for p in probes] != sizes:
            raise ValueError(f"phase {name} probes a different size set")

    hold = next((r for r in records if r["type"] == "hold"), None)
    if hold is None or not hold["ok"]:
        raise ValueError("receipt has no successful full-size hold")

    n = len(sizes)
    before = sum(1 for p in phases["control_before"] if p["ok"])
    under = sum(1 for p in phases["under_hold"] if p["ok"])
    after = sum(1 for p in phases["control_after"] if p["ok"])
    controls_fired = before == n and after == n

    if not controls_fired:
        verdict = "INSTRUMENT_FAILED"
    elif under == 0:
        verdict = "HOLD_CONSUMES_POOL"
    else:
        verdict = "HOLD_LEAVES_ROOM"

    hold_bytes = hold["bytes"]
    exhausted = controls_fired and under == 0
    dt_match = hold_bytes == dt_region["size"]

    return {
        "schema": MANIFEST_SCHEMA,
        "heap": {"name": context["heap"], "heap_type": context["heap_type"],
                 "heap_id": context["heap_id"]},
        "hold_bytes": hold_bytes,
        "probe_sizes_bytes": sizes,
        "smallest_probe_bytes": min(sizes),
        "control_before_ok": before,
        "under_hold_ok": under,
        "control_after_ok": after,
        "probe_count": n,
        "controls_fired": controls_fired,
        "instrument_ok": controls_fired,
        "pool_exhausted": exhausted,
        "verdict": verdict,
        "device_tree_region": {
            k: (hex(v) if isinstance(v, int) and k != "heap_id" else v)
            for k, v in dt_region.items() if k != "end_exclusive"
        },
        "hold_equals_declared_region_size": dt_match,
        "implied_pool_bytes": hold_bytes if exhausted else None,
        "implied_physical_span": (
            [hex(dt_region["base"]), hex(dt_region["end_exclusive"])]
            if exhausted and dt_match else None
        ),
        "implied_physical_span_status": (
            "SUPPORTED_CONDITIONAL_ON_020M_CHAIN" if exhausted and dt_match
            else "NOT_AVAILABLE"
        ),
        "residual_assumption": (
            "The receipt supports no residual allocation at the tested 4 KiB "
            "floor after a 320 MiB hold. Physical pool identity and exact span "
            "remain conditional on the separate 020M heap-30/camera_mem_region "
            "phandle chain; this receipt does not independently re-derive it "
            "or attest the same target."
        ),
        "claim_disposition": {
            "receipt_result": "SUPPORTED_WITHIN_RETAINED_RECEIPT",
            "physical_span": (
                "SUPPORTED_CONDITIONAL_ON_020M_CHAIN" if exhausted and dt_match
                else "UNKNOWN"
            ),
            "target_identity": "UNKNOWN_UNRETAINED",
            "bridge_binding": "UNKNOWN_UNRETAINED",
            "executed_commands": "UNKNOWN_UNRETAINED",
            "classification": "CLASS C (TRANSFORM ONLY)",
            "eligibility": "NOT_ELIGIBLE",
        },
        "not_claimed": (
            "No physical page identity, no complete DRAM coordinate, no value of "
            "f(PA28), no transform mutability and no access-control implication. "
            "This decides allocation extent only."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    records, source = load_records(args.raw, expected_pin=CANONICAL_RAW_PIN)
    dependency = load_020m_dependency()
    result = analyse(records, dependency=dependency, input_metadata=source)
    result["input"] = source
    result["canonical_raw_pin"] = dict(CANONICAL_RAW_PIN)
    result["provenance"] = provenance(source, dependency=dependency)

    print(f"heap            : {result['heap']['name']} (id {result['heap']['heap_id']})")
    print(f"hold            : {result['hold_bytes'] // MIB} MiB")
    print(f"controls fired  : {result['controls_fired']} "
          f"({result['control_before_ok']}/{result['probe_count']} before, "
          f"{result['control_after_ok']}/{result['probe_count']} after)")
    print(f"under hold      : {result['under_hold_ok']}/{result['probe_count']} allocatable, "
          f"smallest probe {result['smallest_probe_bytes'] // 1024} KiB")
    print(f"verdict         : {result['verdict']}")
    if result.get("implied_physical_span"):
        lo, hi = result["implied_physical_span"]
        print(f"implied span    : [{lo}, {hi})")

    if args.output:
        payload = json.dumps(result, indent=1, sort_keys=True).encode() + b"\n"
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
