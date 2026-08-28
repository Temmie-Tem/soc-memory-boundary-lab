#!/usr/bin/env python3
"""Capture the exact read-only DT chain needed before the PA28 test.

This collector does not allocate memory or touch a controller.  It binds the
already-running loopback A90P1 bridge to the explicit A90 ACM device, reads a
fixed allowlist of version/cmdline/DT properties, and publishes a private raw
receipt plus a redacted public manifest.  Missing optional DT properties are
recorded as expected ``ENOENT`` observations rather than silently omitted.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.a90_acm_snapshot import Command, exchange


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "a90-pa28-dt-snapshot-v1"
RAW_SCHEMA = "a90-pa28-dt-snapshot-raw-v1"
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 54321
SERIAL_DEVICE = "/dev/ttyACM0"
SERIAL_ID = "/dev/serial/by-id/usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00"
BRIDGE_SCRIPT = "serial_tcp_bridge.py"
BRIDGE_SCRIPT_PATH = Path("/home/temmie/dev/android-native-init-lab/workspace/public/src/scripts/revalidation/serial_tcp_bridge.py")
EXPECTED_VERSION = "A90 Linux init 0.9.285"
EXPECTED_BUILD = "build=v2321-usb-clean-identity-rodata"
EXPECTED_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
EXPECTED_CMDLINE = frozenset(
    {
        "androidboot.em.model=SM-A908N",
        "androidboot.bootloader=A908NKSU5EWA3",
        "androidboot.debug_level=0x4f4c",
        "androidboot.force_upload=0x0",
        "sec_debug.dump_sink=0x0",
    }
)
HEAP_MANIFEST = ROOT / "evidence/manifests/verification-020-heap-capacity-20260827-01.manifest.json"
HEAP_MANIFEST_SIZE = 4_575
HEAP_MANIFEST_SHA256 = "567ed802dc434965ea7a10d73fd3bea41018826dab6d13f8ea518afce657e043"
MAX_PAYLOAD = 64 * 1024
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}\Z")


COMMANDS: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    ("version", ("version",), False),
    ("cmdline", ("cat", "/proc/cmdline"), False),
    ("ion_list", ("ls", "/sys/firmware/devicetree/base/soc/qcom,ion"), False),
    ("ion_heap30_reg", ("cat", "/sys/firmware/devicetree/base/soc/qcom,ion/qcom,ion-heap@30/reg"), True),
    ("ion_heap30_memory_region", ("cat", "/sys/firmware/devicetree/base/soc/qcom,ion/qcom,ion-heap@30/memory-region"), True),
    ("ion_heap30_name", ("cat", "/sys/firmware/devicetree/base/soc/qcom,ion/qcom,ion-heap@30/name"), False),
    ("camera_reg", ("cat", "/sys/firmware/devicetree/base/reserved-memory/camera_mem_region/reg"), True),
    ("camera_phandle", ("cat", "/sys/firmware/devicetree/base/reserved-memory/camera_mem_region/phandle"), True),
    ("camera_name", ("cat", "/sys/firmware/devicetree/base/reserved-memory/camera_mem_region/name"), False),
    ("camera_ion_recyclable", ("cat", "/sys/firmware/devicetree/base/reserved-memory/camera_mem_region/ion,recyclable"), False),
    ("camera_no_map", ("cat", "/sys/firmware/devicetree/base/reserved-memory/camera_mem_region/no-map"), False),
    ("camera_reusable", ("cat", "/sys/firmware/devicetree/base/reserved-memory/camera_mem_region/reusable"), False),
)


class SnapshotError(RuntimeError):
    """Raised when the exact snapshot contract cannot be satisfied."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def write_new(path: Path, data: bytes, mode: int) -> None:
    _reject_symlink_components(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def read_stable(path: Path, size: int, digest: str, label: str) -> bytes:
    _reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != size:
            raise SnapshotError(f"{label} size/type mismatch")
        data = bytearray()
        while len(data) < size:
            chunk = os.read(fd, min(1 << 20, size - len(data)))
            if not chunk:
                raise SnapshotError(f"{label} truncated")
            data.extend(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise SnapshotError(f"{label} changed while being read")
    result = bytes(data)
    if sha256(result) != digest:
        raise SnapshotError(f"{label} SHA-256 mismatch")
    return result


def _reject_symlink_components(path: Path) -> None:
    """Reject symlinked directory components under the bound repository."""
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(ROOT))
    try:
        relative = absolute.relative_to(root)
    except ValueError as exc:
        raise SnapshotError("path escapes the bound research repository") from exc
    current = root
    for component in relative.parts[:-1]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise SnapshotError(f"symlinked path component is forbidden: {current}")


def bridge_binding() -> dict[str, object]:
    """Bind the current explicit bridge process without changing it."""
    if os.path.realpath(SERIAL_ID) != SERIAL_DEVICE:
        raise SnapshotError("A90 serial by-id path does not resolve to ttyACM0")
    info = os.stat(SERIAL_DEVICE)
    if not stat.S_ISCHR(info.st_mode):
        raise SnapshotError("A90 serial path is not a character device")
    matches: list[dict[str, object]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        argv = [item.decode("utf-8", "replace") for item in raw.split(b"\0") if item]
        if not argv or Path(argv[0]).name != "python3":
            continue
        script_args = [Path(item) for item in argv if Path(item).name == BRIDGE_SCRIPT]
        if not any(item.resolve() == BRIDGE_SCRIPT_PATH.resolve() for item in script_args):
            continue
        if "--device" not in argv or "--host" not in argv or "--port" not in argv:
            continue
        if argv[argv.index("--device") + 1] != SERIAL_DEVICE:
            continue
        if argv[argv.index("--host") + 1] != BRIDGE_HOST:
            continue
        if argv[argv.index("--port") + 1] != str(BRIDGE_PORT):
            continue
        matches.append({"pid": int(entry.name), "argv": argv})
    if len(matches) != 1:
        raise SnapshotError(f"expected one explicit A90 bridge, found {len(matches)}")
    process = matches[0]
    return {
        "listener": {"host": BRIDGE_HOST, "port": BRIDGE_PORT},
        "serial_device": SERIAL_DEVICE,
        "serial_id": SERIAL_ID,
        "serial_realpath": os.path.realpath(SERIAL_ID),
        "process_pid": process["pid"],
        "process_argv": process["argv"],
        "strict_expect_realpath_option": "--expect-realpath" in process["argv"],
        "strict_device_glob_option": "--device-glob" in process["argv"],
    }


def parse_dt_reg(data: bytes, label: str) -> dict[str, object]:
    if not data or len(data) % 4:
        raise SnapshotError(f"{label} has invalid DT cell length {len(data)}")
    cells = [int.from_bytes(data[i : i + 4], "big") for i in range(0, len(data), 4)]
    result: dict[str, object] = {"cells": [f"0x{cell:08x}" for cell in cells]}
    if len(cells) == 4:
        base = (cells[0] << 32) | cells[1]
        size = (cells[2] << 32) | cells[3]
        result.update({"base": f"0x{base:x}", "size": f"0x{size:x}", "end_exclusive": f"0x{base + size:x}"})
    return result


def parse_cell(data: bytes, label: str) -> int:
    if len(data) != 4:
        raise SnapshotError(f"{label} is not one DT cell")
    return int.from_bytes(data, "big")


def parse_text(data: bytes, label: str) -> str:
    try:
        value = data.rstrip(b"\0").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotError(f"{label} is not UTF-8") from exc
    if not value:
        raise SnapshotError(f"{label} is empty")
    return value


def validate_target(version: bytes, cmdline: bytes) -> dict[str, object]:
    version_text = version.decode("utf-8", "strict")
    tokens = set(cmdline.decode("utf-8", "strict").split())
    for expected in (EXPECTED_VERSION, EXPECTED_BUILD, EXPECTED_KERNEL):
        if expected not in version_text:
            raise SnapshotError(f"version lacks exact token: {expected}")
    missing = sorted(EXPECTED_CMDLINE - tokens)
    if missing:
        raise SnapshotError(f"cmdline lacks exact token(s): {missing}")
    return {"model": "SM-A908N", "soc": "SM8150", "version": EXPECTED_VERSION, "build": EXPECTED_BUILD, "kernel": EXPECTED_KERNEL}


def _semantic(records: dict[str, dict[str, object]]) -> dict[str, object]:
    def ok(name: str) -> bytes:
        rec = records[name]
        if rec["rc"] != 0 or rec["status"] != "ok":
            raise SnapshotError(f"{name} did not succeed")
        return base64.b64decode(rec["payload_base64"])

    heap_reg = parse_cell(ok("ion_heap30_reg"), "ion_heap30_reg")
    heap_phandle = parse_cell(ok("ion_heap30_memory_region"), "ion_heap30_memory_region")
    camera_phandle = parse_cell(ok("camera_phandle"), "camera_phandle")
    camera_reg = parse_dt_reg(ok("camera_reg"), "camera_reg")
    absent: dict[str, object] = {}
    for name in ("camera_no_map", "camera_reusable"):
        rec = records[name]
        absent[name] = {"present": rec["rc"] == 0, "errno": rec["errno"], "status": rec["status"]}
        if rec["rc"] != -2 or rec["errno"] != 2:
            raise SnapshotError(f"{name} is not the expected ENOENT absence")
    if heap_reg != 30 or heap_phandle != camera_phandle or camera_reg.get("base") != "0xc2000000" or camera_reg.get("size") != "0x14000000":
        raise SnapshotError("heap-30/camera carveout DT chain changed")
    return {
        "ion_heap30": {"reg": f"0x{heap_reg:x}", "memory_region_phandle": f"0x{heap_phandle:x}", "name": parse_text(ok("ion_heap30_name"), "ion_heap30_name")},
        "camera_mem_region": {"name": parse_text(ok("camera_name"), "camera_name"), "phandle": f"0x{camera_phandle:x}", "reg": camera_reg, "ion_recyclable": {"present": records["camera_ion_recyclable"]["rc"] == 0, "errno": records["camera_ion_recyclable"]["errno"]}, "optional_properties": absent},
        "heap_020_manifest": {"filename": HEAP_MANIFEST.name, "size": HEAP_MANIFEST_SIZE, "sha256": HEAP_MANIFEST_SHA256},
    }


def collect(experiment_id: str, output_root: Path = ROOT) -> tuple[Path, Path]:
    if SAFE_ID.fullmatch(experiment_id) is None:
        raise SnapshotError("invalid experiment id")
    output_root = output_root.resolve()
    if output_root != ROOT.resolve():
        raise SnapshotError("output root must be the bound research repository")
    bridge = bridge_binding()
    heap_manifest = read_stable(HEAP_MANIFEST, HEAP_MANIFEST_SIZE, HEAP_MANIFEST_SHA256, "heap manifest")
    del heap_manifest
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    records: dict[str, dict[str, object]] = {}
    raw_records: list[dict[str, object]] = []
    for evidence_id, argv, _dt in COMMANDS:
        frame = exchange(BRIDGE_HOST, BRIDGE_PORT, Command(evidence_id, argv), 12, allow_error=True)
        if len(frame.payload) > MAX_PAYLOAD:
            raise SnapshotError(f"{evidence_id} payload exceeds bound")
        record = {
            "evidence_id": evidence_id,
            "argv": list(argv),
            "begin": frame.begin,
            "end": frame.end,
            "rc": int(frame.end.get("rc", "-1"), 0),
            "status": frame.end.get("status", "unknown"),
            "errno": int(frame.end.get("errno", "-1"), 0),
            "payload_base64": base64.b64encode(frame.payload).decode("ascii"),
            "payload_sha256": sha256(frame.payload),
            "payload_size": len(frame.payload),
            "transcript_sha256": sha256(frame.transcript),
            "transcript_size": len(frame.transcript),
        }
        records[evidence_id] = record
        raw_records.append(record)
    target = validate_target(base64.b64decode(records["version"]["payload_base64"]), base64.b64decode(records["cmdline"]["payload_base64"]))
    semantic = _semantic(records)
    completed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    raw = {"schema": RAW_SCHEMA, "experiment_id": experiment_id, "started_utc": started, "completed_utc": completed, "target": target, "bridge": bridge, "commands": raw_records, "safety": {"read_only": True, "device_writes": False, "mmio": False, "smc": False, "ion_allocation": False, "protected_memory": False}}
    raw_bytes = json_bytes(raw)
    manifest_records = [{k: record[k] for k in ("evidence_id", "argv", "rc", "status", "errno", "payload_sha256", "payload_size", "transcript_sha256", "transcript_size")} for record in raw_records]
    manifest = {"schema": SCHEMA, "experiment_id": experiment_id, "mode": "DEVICE_READ_ONLY_DT_ONLY", "target": target, "bridge": {k: v for k, v in bridge.items() if k not in {"process_pid", "process_argv"}}, "raw_receipt": {"sha256": sha256(raw_bytes), "size": len(raw_bytes)}, "records": manifest_records, "semantic": semantic, "claims": {"PROVED": ["Exact target identity and the observed heap-30 to camera_mem_region DT phandle/reg chain are retained in the private receipt.", "camera_mem_region no-map and reusable are absent with the expected ENOENT result."], "SUPPORTED": ["The DT chain is consistent with a fixed 320 MiB advertised carveout for heap 30."], "HYPOTHESIS": [], "REFUTED": [], "UNKNOWN": ["Whether a live 320 MiB ION allocation consumes the entire carveout, physical page identity, DRAM coordinates, f(PA28), transform mutability, protection ordering and bypass."]}, "classification": "CLASS C (TRANSFORM ONLY)", "eligibility": "NOT_ELIGIBLE", "device_access": "read_only_dt_only", "boundary_bypass": {"status": "NOT_AUTHORIZED", "protected_memory": False, "controller_write": False, "smc": False}}
    private_dir = output_root / "evidence/private" / experiment_id
    raw_path = private_dir / "dt-snapshot.json"
    manifest_path = output_root / "evidence/manifests" / f"{experiment_id}.manifest.json"
    write_new(raw_path, raw_bytes, 0o600)
    write_new(manifest_path, json_bytes(manifest), 0o644)
    return raw_path, manifest_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--output-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    raw, manifest = collect(args.experiment_id, args.output_root)
    print(f"private receipt: {raw}")
    print(f"public manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
